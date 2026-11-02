"""Run every check against a parsed email and produce a scored verdict."""

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import timedelta

from . import reputation
from .domains import (FREEMAIL, aligned, brand_lookalike, cousin_domain,
                      domain_of, org_domain, BRANDS, brand_label)
from .parser import parse_bytes
from .urls import SHORTENERS, body_parts, extract_urls

SEVERITY_WEIGHT = {"high": 25, "medium": 10, "low": 4, "info": 0}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

MITRE = {
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1656": "Impersonation",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1585.002": "Establish Accounts: Email Accounts",
    "T1036.007": "Masquerading: Double File Extension",
}

URGENCY_TERMS = [
    "urgent", "immediately", "verify your", "suspended", "locked", "unusual activity",
    "action required", "confirm your", "final notice", "within 24 hours",
    "wire transfer", "gift card", "reset your password", "unauthorized",
]
RISKY_EXTENSIONS = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta", "lnk",
    "iso", "img", "html", "htm", "shtml", "svg", "docm", "xlsm", "pptm", "one", "msi",
}
DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|csv)\.[a-z0-9]{2,4}$", re.I)

# Mailers that show up far more in phishing kits and campaign tooling than in normal mail.
SUSPICIOUS_MAILERS = {
    "phpmailer": "PHPMailer, a PHP library bundled with many phishing kits",
    "king phisher": "King Phisher, a phishing campaign toolkit",
    "leaf phpmailer": "Leaf PHPMailer, a mass-mailer sold to spammers",
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""
    mitre: list = field(default_factory=list)
    why: str = ""        # short plain-English clause used in the summary


@dataclass
class Report:
    source: str
    email: object
    findings: list
    urls: list
    attachments: list
    providers: list
    score: int
    verdict: str
    summary: str = ""
    breakdown: dict = field(default_factory=dict)   # category -> points
    iocs: dict = field(default_factory=dict)        # type -> [values]


def _add(findings, severity, category, title, detail="", mitre=(), why=""):
    findings.append(Finding(severity, category, title, detail, list(mitre), why))


def check_authentication(p, findings):
    if not p.has_auth:
        _add(findings, "info", "Authentication", "No authentication results recorded",
             "The message has no Authentication-Results or Received-SPF header, so SPF, DKIM "
             "and DMARC can't be judged. Export the email from the recipient's mailbox "
             "(not the sender's Sent folder) to include them.")
        return

    spf, dkim, dmarc = p.auth_status("spf"), p.auth_status("dkim"), p.auth_status("dmarc")
    # A passing ARC chain means a trusted intermediary (mailing list, forwarder) vouches
    # for the original authentication, so SPF breakage is expected.
    forwarded = p.auth_status("arc") == "pass"

    if spf in ("fail", "permerror"):
        _add(findings, "medium" if forwarded else "high", "Authentication", f"SPF {spf}",
             "The sending server is not authorized to send for the envelope domain."
             + (" ARC passed, so this may be caused by forwarding." if forwarded else ""),
             ["T1566"])
    elif spf == "softfail":
        _add(findings, "low" if forwarded else "medium", "Authentication", "SPF softfail",
             "The domain owner says this server probably isn't theirs (~all).", ["T1566"])
    elif spf in ("none", "neutral", "temperror"):
        _add(findings, "low", "Authentication", f"SPF {spf}", "No usable SPF verdict.")

    if dkim in ("fail", "permerror"):
        _add(findings, "high", "Authentication", "DKIM signature failed",
             "The message was altered in transit or the signature is forged.", ["T1566"])
    elif dkim in ("none", "neutral", "temperror"):
        _add(findings, "medium" if not p.dkim_signatures else "low", "Authentication",
             "No valid DKIM signature", "The message carries no verifiable DKIM signature.")

    if dmarc == "fail":
        _add(findings, "high", "Authentication", "DMARC fail",
             "Neither SPF nor DKIM passed in alignment with the visible From domain. "
             "This is the strongest single indicator of a spoofed sender.", ["T1566", "T1656"],
             why="it failed DMARC, so the From address is very likely forged")
    elif dmarc in ("none", "temperror", "permerror"):
        _add(findings, "low", "Authentication", f"DMARC {dmarc}",
             "The From domain has no enforceable DMARC result.")

    if p.auth_status("compauth") == "fail" and dmarc != "fail":
        _add(findings, "medium", "Authentication", "Microsoft composite authentication failed",
             "Exchange Online's compauth combined SPF, DKIM, DMARC and sender reputation "
             "and judged the sender unauthenticated.", ["T1566"])

    # DKIM passed, but for someone else's domain (common with spoofing via bulk senders).
    dkim_domains = [r.props.get("header.d", "") for r in p.auth("dkim") if r.result == "pass"]
    if dkim_domains and p.from_domain and not any(aligned(d, p.from_domain) for d in dkim_domains):
        _add(findings, "medium", "Authentication", "DKIM signer not aligned with From",
             f"Signed by {', '.join(dkim_domains)}, but From is {p.from_domain}.")


def check_sender_identity(p, findings, dmarc_pass):
    fd = p.from_domain
    if not fd:
        _add(findings, "medium", "Sender", "From header missing or malformed")
        return

    rp_domain = domain_of(p.return_path)
    if rp_domain and not aligned(rp_domain, fd):
        # Mail sent through an ESP often has a mismatched Return-Path but still passes DMARC.
        _add(findings, "low" if dmarc_pass else "medium", "Sender", "Return-Path does not match From",
             f"Bounces go to {p.return_path}, but the message claims to be from {p.from_addr}.",
             [] if dmarc_pass else ["T1566"])

    rt_domain = domain_of(p.reply_to)
    if rt_domain and not aligned(rt_domain, fd):
        if rt_domain in FREEMAIL and fd not in FREEMAIL:
            _add(findings, "high", "Sender", "Replies redirected to a free webmail account",
                 f"Reply-To is {p.reply_to} while From is {p.from_addr}. "
                 "This is a hallmark of business email compromise (BEC).",
                 ["T1566", "T1585.002"], why=f"replies are secretly redirected to {p.reply_to}")
        else:
            _add(findings, "medium", "Sender", "Reply-To differs from From",
                 f"Replies go to {p.reply_to}, not {p.from_addr}.", ["T1566"])

    sender_domain = domain_of(p.sender)
    if sender_domain and not aligned(sender_domain, fd):
        _add(findings, "low", "Sender", "Sent on behalf of another domain",
             f"Sender header is {p.sender} while From is {p.from_addr}.")

    # Display name containing an email address for a different domain: "support@paypal.com <x@evil.ru>"
    shown = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", p.from_name or "")
    if shown and not aligned(shown.group(1), fd):
        _add(findings, "high", "Sender", "Display name contains a different email address",
             f"Shows '{p.from_name}' but the real sender is {p.from_addr}.", ["T1656"],
             why=f"the display name shows {shown.group(0)} but the real sender is {p.from_addr}")

    # Display name claims to be a brand the domain doesn't belong to.
    name = re.sub(r"[^a-z0-9]", "", (p.from_name or "").lower())
    for brand, legit in BRANDS.items():
        if brand in name and org_domain(fd) not in legit:
            label = brand_label(brand)
            _add(findings, "high", "Sender", f"Display name impersonates {label}",
                 f"'{p.from_name}' is sent from {fd}, which is not a {label} domain.",
                 ["T1656"], why=f"it claims to be from {label} but was sent from {fd}")
            break

    lookalike = brand_lookalike(fd)
    if lookalike:
        label = brand_label(lookalike[0])
        _add(findings, "high", "Sender", f"Sender domain imitates {label}",
             f"{fd} {lookalike[1]}.", ["T1583.001", "T1656"],
             why=f"the sender domain {fd} is a lookalike of {label}")

    for rcpt in p.to:
        if cousin_domain(fd, domain_of(rcpt)):
            _add(findings, "high", "Sender", "Sender domain imitates the recipient's organization",
                 f"{fd} is a near-copy of {domain_of(rcpt)}. Attackers register these "
                 "'cousin domains' to pose as coworkers.", ["T1583.001", "T1656"],
                 why=f"{fd} is a lookalike of the recipient's own domain {domain_of(rcpt)}")
            break

    mid = re.search(r"@([^>\s]+)>?$", p.message_id or "")
    if mid and not aligned(mid.group(1), fd) and not dmarc_pass:
        _add(findings, "low", "Sender", "Message-ID domain differs from From",
             f"Message-ID was generated by {mid.group(1)}.")


def _comparable(a, b):
    """Both datetimes timezone-aware (or both naive), so they can be subtracted."""
    return a is not None and b is not None and (a.tzinfo is None) == (b.tzinfo is None)


def check_headers(p, findings):
    """Structural header anomalies: timing, missing fields, sending software."""
    if not p.message_id:
        _add(findings, "low", "Header", "Missing Message-ID",
             "Every mail client and legitimate server adds one; bulk-mailing scripts often don't.")
    if not p.date:
        _add(findings, "low", "Header", "Missing Date header")

    stamps = [h.timestamp for h in p.hops if h.timestamp]
    if stamps and _comparable(p.date_dt, stamps[0]) and _comparable(p.date_dt, stamps[-1]):
        if p.date_dt > stamps[-1] + timedelta(minutes=15):
            _add(findings, "medium", "Header", "Date header is later than delivery",
                 f"Claims to be written at {p.date_dt:%Y-%m-%d %H:%M %z}, after the final "
                 f"server received it ({stamps[-1]:%Y-%m-%d %H:%M %z}). The Date was forged.")
        elif p.date_dt < stamps[0] - timedelta(days=1):
            _add(findings, "medium", "Header", "Date header is backdated",
                 f"Claims {p.date_dt:%Y-%m-%d %H:%M %z}, more than a day before the first "
                 f"server saw it ({stamps[0]:%Y-%m-%d %H:%M %z}).")

    if any(h.delay_s is not None and h.delay_s < -300 for h in p.hops):
        _add(findings, "low", "Header", "Received timestamps out of order",
             "A later hop is stamped more than 5 minutes before an earlier one. Some Received "
             "headers may have been forged to disguise the true origin.")

    mailer = (p.mailer or "").lower()
    if "gophish" in mailer or "x-gophish-contact" in p.extra_headers:
        _add(findings, "medium", "Header", "Sent with GoPhish",
             "GoPhish is a phishing-simulation framework. This is probably an authorized "
             "security-awareness test; confirm with your security team before escalating.")
    else:
        for needle, desc in SUSPICIOUS_MAILERS.items():
            if needle in mailer:
                _add(findings, "low", "Header", f"Sent with {p.mailer}",
                     f"The X-Mailer identifies {desc}.")
                break


def check_content(p, findings):
    text = p.subject.lower() + " " + " ".join(t.lower() for _, t in body_parts(p.message))
    hits = [t for t in URGENCY_TERMS if re.search(r"\b" + re.escape(t) + r"\b", text)]
    if hits:
        _add(findings, "medium" if len(hits) >= 3 else "low", "Content",
             "Urgency / pressure language", "Matched: " + ", ".join(f"'{h}'" for h in hits),
             why="it pressures the reader to act quickly" if len(hits) >= 3 else "")


def check_attachments(p, findings):
    attachments = []
    for part in p.message.walk():
        name = part.get_filename()
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append({"filename": name, "content_type": part.get_content_type(),
                            "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if DOUBLE_EXT_RE.search(name):
            _add(findings, "high", "Attachment", f"Double file extension: {name}",
                 "The real file type is hidden behind a harmless-looking extension.",
                 ["T1566.001", "T1036.007"],
                 why=f"the attachment {name} disguises its real file type")
        elif ext in RISKY_EXTENSIONS:
            _add(findings, "high", "Attachment", f"Risky attachment type: {name}",
                 f".{ext} files can run code or host credential-harvesting pages locally.",
                 ["T1566.001"], why=f"it carries a risky .{ext} attachment")
    return attachments


def check_urls(urls, findings):
    for u in urls:
        worst = min((sev for sev, _ in u.flags), key=SEVERITY_ORDER.get, default=None)
        if worst in ("high", "medium"):
            _add(findings, worst, "URL", f"Suspicious link: {u.host or u.url}",
                 "; ".join(reason for _, reason in u.flags), ["T1566.002"],
                 why="LINK" if worst == "high" else "")
        for provider, verdict, detail in u.reputation:
            if verdict in ("malicious", "suspicious"):
                _add(findings, "high" if verdict == "malicious" else "medium", "Reputation",
                     f"{provider} flags {u.host}", detail, ["T1566.002"],
                     why=f"{provider} reports {u.host} as {verdict}")


def score_findings(findings):
    score = min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))
    if score >= 60:
        return score, "LIKELY PHISHING"
    if score >= 25:
        return score, "SUSPICIOUS"
    return score, "LIKELY LEGITIMATE"


def score_breakdown(findings):
    points = {}
    for f in findings:
        if SEVERITY_WEIGHT[f.severity]:
            points[f.category] = points.get(f.category, 0) + SEVERITY_WEIGHT[f.severity]
    return dict(sorted(points.items(), key=lambda kv: -kv[1]))


def summarize(p, findings, verdict):
    """One or two plain-English sentences a non-specialist can act on."""
    all_pass = all(p.auth_status(m) == "pass" for m in ("spf", "dkim", "dmarc"))
    reasons, links = [], 0
    for f in findings:
        if f.why == "LINK":
            links += 1
        elif f.why and f.why not in reasons:
            reasons.append(f.why)
    if links:
        reasons.insert(min(2, len(reasons)),
                       f"{links} link{'s are' if links > 1 else ' is'} deceptive")

    if verdict == "LIKELY LEGITIMATE":
        text = "No significant phishing indicators were found"
        if all_pass:
            text += ", and the message passes SPF, DKIM and DMARC"
        return text + "."

    opener = "This email is very likely phishing" if verdict == "LIKELY PHISHING" \
        else "This email shows warning signs"
    picked = reasons[:3]
    if not picked:
        text = opener + "."
    elif len(picked) == 1:
        text = f"{opener}: {picked[0]}."
    else:
        text = f"{opener}: {'; '.join(picked[:-1])}; and {picked[-1]}."
    if all_pass and verdict == "LIKELY PHISHING":
        text += (" It passes SPF, DKIM and DMARC, which means the attacker controls the "
                 "sending domain rather than spoofing someone else's.")
    return text


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_iocs(p, urls, attachments, verdict):
    """Indicators an analyst would block or hunt for. Empty for legitimate mail."""
    if verdict == "LIKELY LEGITIMATE":
        return {}
    legit = set().union(*BRANDS.values())
    flagged = [u for u in urls if u.flags or any(v == "malicious" for _, v, _ in u.reputation)]

    domains, ips = [], []
    for d in [p.from_domain, domain_of(p.return_path), domain_of(p.reply_to)] + [u.host for u in flagged]:
        if not d:
            continue
        target = ips if _is_ip(d) else domains
        if d not in target and d not in FREEMAIL | SHORTENERS and org_domain(d) not in legit:
            target.append(d)
    if p.originating_ip and p.originating_ip not in ips:
        ips.insert(0, p.originating_ip)

    iocs = {
        "urls": [u.url for u in flagged],
        "domains": domains,
        "ips": ips,
        "emails": list(dict.fromkeys(a for a in (p.from_addr, p.reply_to, p.return_path) if a)),
        "sha256": [a["sha256"] for a in attachments],
    }
    return {k: v for k, v in iocs.items() if v}


def analyze(raw, source="<stdin>", online=False, max_urls=10):
    p = parse_bytes(raw)
    if not (p.from_addr or p.subject or p.hops):
        raise ValueError("input doesn't look like an email (no From, Subject or Received headers)")
    findings = []

    check_authentication(p, findings)
    check_sender_identity(p, findings, dmarc_pass=p.auth_status("dmarc") == "pass")
    check_headers(p, findings)
    check_content(p, findings)
    attachments = check_attachments(p, findings)

    urls = extract_urls(p.message)
    providers = reputation.enrich(urls, max_urls) if online else []
    check_urls(urls, findings)

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    score, verdict = score_findings(findings)
    return Report(source, p, findings, urls, attachments, providers, score, verdict,
                  summary=summarize(p, findings, verdict),
                  breakdown=score_breakdown(findings),
                  iocs=extract_iocs(p, urls, attachments, verdict))
