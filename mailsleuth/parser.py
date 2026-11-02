"""Parse a raw email into the header fields an analyst cares about."""

import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from .domains import domain_of

AR_METHOD_RE = re.compile(r"(?<![.\w])(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)([^;]*)", re.I)
AR_PROP_RE = re.compile(r"\b([a-z]+\.[a-z\-]+)\s*=\s*\"?([^\s;\"()]+)", re.I)
DKIM_TAG_RE = re.compile(r"\b([a-z]+)\s*=\s*([^;]*)", re.I)
RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]+)\]", re.I)
RECEIVED_FROM_RE = re.compile(r"\bfrom\s+([^\s;()]+)", re.I)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.I)

PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
)]


@dataclass
class AuthResult:
    method: str          # spf / dkim / dmarc / arc
    result: str          # pass / fail / softfail / none / ...
    props: dict = field(default_factory=dict)  # header.d, smtp.mailfrom, header.from, ...


@dataclass
class Hop:
    from_host: str
    by_host: str
    ip: str
    timestamp: object    # datetime or None
    delay_s: object = None


@dataclass
class ParsedEmail:
    message: object
    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_name: str = ""
    from_addr: str = ""
    return_path: str = ""
    reply_to: str = ""
    sender: str = ""
    to: list = field(default_factory=list)
    auth_results: list = field(default_factory=list)
    authserv_id: str = ""
    received_spf: str = ""
    dkim_signatures: list = field(default_factory=list)  # [{"d": ..., "s": ...}]
    hops: list = field(default_factory=list)              # chronological
    originating_ip: str = ""
    date_dt: object = None
    mailer: str = ""
    extra_headers: set = field(default_factory=set)       # lowercased header names

    @property
    def has_auth(self):
        """Whether the receiving server recorded any authentication verdict at all."""
        return bool(self.auth_results or self.received_spf)

    @property
    def from_domain(self):
        return domain_of(self.from_addr)

    def auth(self, method):
        """All results for one method (e.g. every dkim= entry)."""
        return [r for r in self.auth_results if r.method == method]

    def auth_status(self, method):
        """Single best verdict for a method: pass if anything passed, else the first result."""
        results = self.auth(method)
        if method == "spf" and not results and self.received_spf:
            return self.received_spf
        if not results:
            return "none"
        if any(r.result == "pass" for r in results):
            return "pass"
        return results[0].result


def _clean(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _strip_comments(value):
    """Remove (comments), which can contain look-alike text such as Gmail's
    'arc=pass (i=1 spf=pass dkim=pass ...)'."""
    out, depth = [], 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


def parse_authentication_results(value):
    """Parse one Authentication-Results header (RFC 8601)."""
    value = _strip_comments(_clean(value))
    authserv_id, _, rest = value.partition(";")
    results = []
    for method, result, tail in AR_METHOD_RE.findall(rest):
        props = {k.lower(): v.strip(">").lower() for k, v in AR_PROP_RE.findall(tail)}
        results.append(AuthResult(method.lower(), result.lower(), props))
    return authserv_id.strip(), results


def parse_dkim_signature(value):
    tags = {k.lower(): _clean(v) for k, v in DKIM_TAG_RE.findall(_clean(value))}
    return {"d": tags.get("d", "").lower(), "s": tags.get("s", "")}


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in PRIVATE_NETS if net.version == addr.version)


def parse_received(values):
    """Turn Received headers (newest first) into a chronological list of hops."""
    hops = []
    for raw in reversed(values):
        raw = _clean(raw)
        body, _, date_part = raw.rpartition(";")
        ip_match = RECEIVED_IP_RE.search(body or raw)
        from_match = RECEIVED_FROM_RE.search(body or raw)
        by_match = RECEIVED_BY_RE.search(body or raw)
        try:
            ts = parsedate_to_datetime(date_part.strip()) if date_part else None
        except (TypeError, ValueError):
            ts = None
        hops.append(Hop(
            from_host=from_match.group(1) if from_match else "",
            by_host=by_match.group(1) if by_match else "",
            ip=ip_match.group(1) if ip_match else "",
            timestamp=ts,
        ))
    for prev, cur in zip(hops, hops[1:]):
        if prev.timestamp and cur.timestamp:
            try:
                cur.delay_s = int((cur.timestamp - prev.timestamp).total_seconds())
            except TypeError:  # naive vs aware datetimes
                pass
    return hops


def parse_bytes(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    p = ParsedEmail(message=msg)

    p.subject = _clean(msg.get("Subject"))
    p.date = _clean(msg.get("Date"))
    try:
        p.date_dt = parsedate_to_datetime(p.date) if p.date else None
    except (TypeError, ValueError):
        p.date_dt = None
    p.message_id = _clean(msg.get("Message-ID"))
    p.mailer = _clean(msg.get("X-Mailer") or msg.get("User-Agent"))
    p.extra_headers = {k.lower() for k in msg.keys()}
    p.from_name, p.from_addr = parseaddr(_clean(msg.get("From")))
    p.from_addr = p.from_addr.lower()
    p.return_path = parseaddr(_clean(msg.get("Return-Path")))[1].lower()
    p.reply_to = parseaddr(_clean(msg.get("Reply-To")))[1].lower()
    p.sender = parseaddr(_clean(msg.get("Sender")))[1].lower()
    p.to = [addr.lower() for _, addr in getaddresses([_clean(v) for v in msg.get_all("To", [])]) if addr]

    # The topmost Authentication-Results header is the one stamped by the
    # receiving server. Lower ones could have been injected by the sender.
    ar_headers = msg.get_all("Authentication-Results", [])
    if ar_headers:
        p.authserv_id, p.auth_results = parse_authentication_results(ar_headers[0])

    spf_headers = msg.get_all("Received-SPF", [])
    if spf_headers:
        p.received_spf = _clean(spf_headers[0]).split(" ", 1)[0].lower()

    p.dkim_signatures = [parse_dkim_signature(v) for v in msg.get_all("DKIM-Signature", [])]

    p.hops = parse_received(msg.get_all("Received", []))
    p.originating_ip = next((h.ip for h in p.hops if h.ip and is_public_ip(h.ip)), "")
    return p


def parse_file(path):
    with open(path, "rb") as fh:
        return parse_bytes(fh.read())
