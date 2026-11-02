"""Extract URLs from an email body and flag suspicious ones offline."""

import html
import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .domains import brand_lookalike, is_punycode, org_domain

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf",
    "work", "rest", "support", "cam", "icu", "buzz", "monster",
}


@dataclass
class ExtractedURL:
    url: str
    anchor_text: str = ""
    source: str = "text"          # text / html-link / html-form
    flags: list = field(default_factory=list)  # [(severity, reason)]
    reputation: list = field(default_factory=list)  # [(provider, verdict, detail)]

    @property
    def host(self):
        try:
            return (urlsplit(self.url).hostname or "").lower()
        except ValueError:
            return ""


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []          # [(href, text, source)]
        self._open = None        # [href, text_chunks]

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._open = [attrs["href"], []]
        elif tag == "form" and attrs.get("action"):
            self.links.append((attrs["action"], "", "html-form"))

    def handle_data(self, data):
        if self._open is not None:
            self._open[1].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._open is not None:
            href, chunks = self._open
            self.links.append((href, " ".join("".join(chunks).split()), "html-link"))
            self._open = None


def body_parts(message):
    """Yield (content_type, text) for every text/plain and text/html part."""
    for part in message.walk():
        if part.is_multipart() or part.get_filename():
            continue
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                yield ctype, part.get_content()
            except (LookupError, UnicodeDecodeError, AssertionError):
                payload = part.get_payload(decode=True) or b""
                yield ctype, payload.decode("utf-8", "replace")


def extract_urls(message):
    found = {}
    for ctype, text in body_parts(message):
        if ctype == "text/html":
            parser = _LinkParser()
            parser.feed(text)
            for href, anchor, source in parser.links:
                if href.lower().startswith(("http://", "https://")):
                    found.setdefault(href, ExtractedURL(href, anchor, source))
            text = html.unescape(text)
        for url in URL_RE.findall(text):
            url = url.rstrip(".,;:!?")
            found.setdefault(url, ExtractedURL(url))
    urls = list(found.values())
    for u in urls:
        u.flags = analyze_url(u.url, u.anchor_text)
    return urls


def _ip_host(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return host.isdigit() or bool(re.fullmatch(r"0x[0-9a-f]+", host))  # decimal/hex IP tricks


def analyze_url(url, anchor_text=""):
    flags = []
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return [("medium", "Malformed URL")]

    if parts.username or "@" in parts.netloc:
        flags.append(("high", "Userinfo '@' in URL hides the real destination host"))
    if _ip_host(host):
        flags.append(("high", "Links to a raw IP address instead of a domain"))
    if is_punycode(host):
        flags.append(("high", "Punycode (internationalized) domain, possible homograph attack"))
    if org_domain(host) in SHORTENERS:
        flags.append(("medium", "URL shortener hides the final destination"))
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        flags.append(("medium", f"Uncommon TLD '.{host.rsplit('.', 1)[-1]}' frequently abused for phishing"))
    if parts.scheme == "http":
        flags.append(("low", "Unencrypted http:// link"))
    if host.count(".") >= 4:
        flags.append(("low", "Unusually deep subdomain nesting"))

    lookalike = brand_lookalike(host)
    if lookalike:
        flags.append(("high", f"Lookalike domain: {lookalike[1]}"))

    if anchor_text:
        shown = DOMAIN_IN_TEXT_RE.findall(anchor_text)
        if shown and all(org_domain(d) != org_domain(host) for d in shown):
            flags.append(("high", f"Link text shows '{shown[0]}' but points to '{host}'"))
    return flags


def defang(url):
    """Make a URL safe to paste into tickets: hxxps://evil[.]com/path."""
    url = re.sub(r"^http", "hxxp", url, flags=re.I)
    try:
        host = urlsplit(url).netloc
    except ValueError:
        return url.replace(".", "[.]")
    return url.replace(host, host.replace(".", "[.]"), 1)
