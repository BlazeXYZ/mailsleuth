"""Render a Report as terminal text, JSON, or a standalone HTML page."""

import json
import textwrap
from datetime import datetime
from html import escape

from .analyzer import MITRE
from .urls import defang

ANSI = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[90m",
        "bold": "\033[1m", "dim": "\033[2m", "green": "\033[92m", "reset": "\033[0m"}
VERDICT_COLOR = {"LIKELY PHISHING": "high", "SUSPICIOUS": "medium", "LIKELY LEGITIMATE": "green"}
AUTH_COLOR = {"pass": "green", "fail": "high", "softfail": "medium", "permerror": "high"}
IOC_LABELS = {"urls": "URLs", "domains": "Domains", "ips": "IP addresses",
              "emails": "Email addresses", "sha256": "Attachment SHA-256"}
CATEGORY_COLORS = {"Authentication": "#6d5efc", "Sender": "#e0457b", "URL": "#f2994a",
                   "Attachment": "#2bb3a3", "Header": "#3fa7f5", "Content": "#8a94a6",
                   "Reputation": "#c2410c"}


def mitre_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def defang_ioc(kind, value):
    """Defang an indicator so it can't be clicked by accident in a ticket or chat."""
    if kind == "urls":
        return defang(value)
    if kind in ("domains", "ips"):
        return value.replace(".", "[.]")
    if kind == "emails":
        user, _, domain = value.rpartition("@")
        return f"{user}[@]{domain.replace('.', '[.]')}"
    return value


def auth_label(p, method):
    return p.auth_status(method) if p.has_auth else "n/a"


# --------------------------------------------------------------------------- terminal

def to_terminal(r, color=True):
    c = (lambda key: ANSI[key]) if color else (lambda key: "")
    p = r.email
    out = []
    line = c("dim") + "─" * 72 + c("reset")

    out.append(line)
    out.append(f"{c('bold')}MailSleuth{c('reset')}  {r.source}")
    out.append(f"{c(VERDICT_COLOR[r.verdict])}{c('bold')}{r.verdict}{c('reset')}  "
               f"risk score {r.score}/100")
    out.extend(textwrap.wrap(r.summary, 72))
    if r.breakdown:
        out.append(c("dim") + "Points: " + " · ".join(f"{k} {v}" for k, v in r.breakdown.items())
                   + c("reset"))
    out.append(line)

    rows = [("Subject", p.subject), ("From", f"{p.from_name} <{p.from_addr}>".strip()),
            ("Return-Path", p.return_path), ("Reply-To", p.reply_to), ("To", ", ".join(p.to)),
            ("Date", p.date), ("Origin IP", p.originating_ip), ("Mailer", p.mailer)]
    for label, value in rows:
        if value and value.strip(" <>"):
            out.append(f"  {label:<12} {value}")

    auth = []
    for m in ("spf", "dkim", "dmarc"):
        status = auth_label(p, m)
        auth.append(f"{m.upper()} {c(AUTH_COLOR.get(status, 'medium'))}{status}{c('reset')}")
    out.append(f"  {'Auth':<12} " + "   ".join(auth))
    out.append("")

    out.append(f"{c('bold')}Findings ({len(r.findings)}){c('reset')}")
    if not r.findings:
        out.append("  none")
    for f in r.findings:
        tags = f"  {c('dim')}[{', '.join(f.mitre)}]{c('reset')}" if f.mitre else ""
        out.append(f"  {c(f.severity)}{f.severity.upper():<7}{c('reset')} {f.title}{tags}")
        if f.detail:
            out.append(f"          {c('dim')}{f.detail}{c('reset')}")
    out.append("")

    if r.urls:
        out.append(f"{c('bold')}URLs ({len(r.urls)}, defanged){c('reset')}")
        for u in r.urls:
            mark = c("high") + "!" if u.flags else c("green") + "·"
            out.append(f"  {mark}{c('reset')} {defang(u.url)}")
            for sev, reason in u.flags:
                out.append(f"      {c(sev)}{reason}{c('reset')}")
            for provider, verdict, detail in u.reputation:
                out.append(f"      {provider}: {verdict} ({detail})")
        out.append("")

    if r.attachments:
        out.append(f"{c('bold')}Attachments{c('reset')}")
        for a in r.attachments:
            out.append(f"  {a['filename']}  ({a['content_type']}, {a['size']} bytes)")
            out.append(f"      {c('dim')}sha256 {a['sha256']}{c('reset')}")
        out.append("")

    if r.iocs:
        out.append(f"{c('bold')}Indicators of compromise (defanged){c('reset')}")
        for kind, values in r.iocs.items():
            out.append(f"  {IOC_LABELS[kind]}")
            out.extend(f"    {defang_ioc(kind, v)}" for v in values)
        out.append("")

    if p.hops:
        out.append(f"{c('bold')}Received chain (oldest first){c('reset')}")
        for i, h in enumerate(p.hops, 1):
            delay = f" +{h.delay_s}s" if h.delay_s is not None else ""
            out.append(f"  {i}. {h.from_host or '?'} [{h.ip or '?'}] → {h.by_host or '?'}{delay}")
    return "\n".join(out)


# --------------------------------------------------------------------------- json

def to_dict(r):
    p = r.email
    return {
        "source": r.source,
        "verdict": r.verdict,
        "score": r.score,
        "summary": r.summary,
        "score_breakdown": r.breakdown,
        "headers": {
            "subject": p.subject, "date": p.date, "message_id": p.message_id,
            "from_name": p.from_name, "from": p.from_addr, "return_path": p.return_path,
            "reply_to": p.reply_to, "sender": p.sender, "to": p.to,
            "originating_ip": p.originating_ip, "mailer": p.mailer,
        },
        "authentication": {
            "authserv_id": p.authserv_id,
            "spf": auth_label(p, "spf"), "dkim": auth_label(p, "dkim"),
            "dmarc": auth_label(p, "dmarc"),
            "raw": [{"method": a.method, "result": a.result, **a.props} for a in p.auth_results],
            "dkim_signatures": p.dkim_signatures,
        },
        "findings": [{"severity": f.severity, "category": f.category, "title": f.title,
                      "detail": f.detail, "mitre": f.mitre} for f in r.findings],
        "urls": [{"url": u.url, "defanged": defang(u.url), "anchor_text": u.anchor_text,
                  "flags": [{"severity": s, "reason": m} for s, m in u.flags],
                  "reputation": [{"provider": a, "verdict": b, "detail": d}
                                 for a, b, d in u.reputation]} for u in r.urls],
        "attachments": r.attachments,
        "iocs": r.iocs,
        "received_chain": [{"from": h.from_host, "by": h.by_host, "ip": h.ip,
                            "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                            "delay_s": h.delay_s} for h in p.hops],
        "reputation_providers": r.providers,
    }


def to_json(reports):
    data = [to_dict(r) for r in reports]
    return json.dumps(data[0] if len(data) == 1 else data, indent=2)


# --------------------------------------------------------------------------- html

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5d6673;--line:#e3e6eb;
--high:#d7263d;--medium:#d98a00;--low:#1f7fb8;--ok:#1a9a5a;--chip:#eef0f3;
--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f13;--card:#151920;--ink:#e6e9ee;
--muted:#8b95a3;--line:#252b35;--high:#ff5468;--medium:#ffb020;--low:#4fb3ff;--ok:#38d68a;--chip:#1e242d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 64px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:.04em}
.src{color:var(--muted);font-family:var(--mono);font-size:13px;word-break:break-all}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:16px}
.verdict{border-left:6px solid var(--vc)}
.vhead{display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.verdict h1{margin:0;font-size:28px;color:var(--vc);letter-spacing:.02em}
.summary{margin:14px 0 0;font-size:16px;max-width:75ch}
.meter{flex:1;min-width:200px}.bar{height:10px;background:var(--chip);border-radius:99px;overflow:hidden}
.bar span{display:block;height:100%;background:var(--vc)}
.meter small{color:var(--muted)}
.stack{display:flex;height:8px;border-radius:99px;overflow:hidden;margin-top:16px;gap:2px}
.legend{display:flex;flex-wrap:wrap;gap:4px 16px;margin-top:8px;font-size:13px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 12px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}
dt{color:var(--muted)}dd{margin:0;font-family:var(--mono);font-size:13px;word-break:break-all}
.auth{display:flex;gap:12px;flex-wrap:wrap}
.pill{border-radius:10px;padding:10px 16px;background:var(--chip);min-width:120px}
.pill b{display:block;font-size:12px;color:var(--muted);letter-spacing:.08em}
.pill span{font-family:var(--mono);font-size:18px;font-weight:700}
.pass{color:var(--ok)}.fail,.permerror{color:var(--high)}.softfail,.none,.neutral,.temperror{color:var(--medium)}
.n\\/a{color:var(--muted)}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px 8px;border-top:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;border-top:0}
.sev{font-family:var(--mono);font-size:12px;font-weight:700;padding:2px 8px;border-radius:6px;color:#fff}
.sev.high{background:var(--high)}.sev.medium{background:var(--medium);color:#1d1400}.sev.low{background:var(--low)}
.sev.info{background:var(--chip);color:var(--muted)}
.detail{color:var(--muted);font-size:14px}
.tag{display:inline-block;font-family:var(--mono);font-size:12px;background:var(--chip);
color:var(--ink);padding:1px 6px;border-radius:5px;margin:2px 4px 0 0;text-decoration:none}
.tag:hover{outline:1px solid var(--muted)}
.url{font-family:var(--mono);font-size:13px;word-break:break-all}
ul.flags{margin:6px 0 0;padding-left:18px;font-size:13px}
.f-high{color:var(--high)}.f-medium{color:var(--medium)}.f-low{color:var(--low)}
.table-wrap{overflow-x:auto}
textarea{width:100%;min-height:140px;resize:vertical;background:var(--chip);color:var(--ink);
border:1px solid var(--line);border-radius:8px;padding:12px;font:13px/1.5 var(--mono)}
.hint{color:var(--muted);font-size:13px;margin:0 0 10px}
footer{color:var(--muted);font-size:12px;margin-top:24px;text-align:center}
"""

VERDICT_CSS = {"LIKELY PHISHING": "var(--high)", "SUSPICIOUS": "var(--medium)",
               "LIKELY LEGITIMATE": "var(--ok)"}


def to_html(r):
    p = r.email
    e = lambda v: escape(str(v or ""))  # noqa: E731

    def tags(ids):
        return "".join(f'<a class="tag" href="{mitre_url(t)}" target="_blank" rel="noopener" '
                       f'title="{e(MITRE.get(t, ""))}">{e(t)}</a>' for t in ids)

    breakdown_html = ""
    if r.breakdown:
        segments = "".join(
            f'<span style="flex:{pts};background:{CATEGORY_COLORS.get(cat, "#888")}" '
            f'title="{e(cat)}: {pts} points"></span>' for cat, pts in r.breakdown.items())
        legend = "".join(f'<span><i style="background:{CATEGORY_COLORS.get(cat, "#888")}"></i>'
                         f'{e(cat)} {pts}</span>' for cat, pts in r.breakdown.items())
        breakdown_html = f'<div class="stack">{segments}</div><div class="legend">{legend}</div>'

    header_rows = [("Subject", p.subject), ("From", f"{p.from_name} <{p.from_addr}>"),
                   ("Return-Path", p.return_path), ("Reply-To", p.reply_to), ("Sender", p.sender),
                   ("To", ", ".join(p.to)), ("Date", p.date), ("Message-ID", p.message_id),
                   ("Originating IP", p.originating_ip), ("Mailer", p.mailer),
                   ("Auth server", p.authserv_id)]
    headers_html = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in header_rows
                           if v and v.strip(" <>"))

    auth_html = "".join(
        f'<div class="pill"><b>{m.upper()}</b><span class="{e(s)}">{e(s)}</span></div>'
        for m, s in ((m, auth_label(p, m)) for m in ("spf", "dkim", "dmarc")))

    if r.findings:
        rows = "".join(
            f'<tr><td><span class="sev {f.severity}">{f.severity.upper()}</span></td>'
            f'<td><b>{e(f.title)}</b><div class="detail">{e(f.detail)}</div></td>'
            f'<td>{e(f.category)}</td><td>{tags(f.mitre)}</td></tr>' for f in r.findings)
        findings_html = (f'<div class="table-wrap"><table><tr><th>Severity</th><th>Finding</th>'
                         f'<th>Category</th><th>ATT&amp;CK</th></tr>{rows}</table></div>')
    else:
        findings_html = "<p>No findings.</p>"

    ioc_html = ""
    if r.iocs:
        lines = []
        for kind, values in r.iocs.items():
            lines.append(f"# {IOC_LABELS[kind]}")
            lines.extend(defang_ioc(kind, v) for v in values)
            lines.append("")
        ioc_html = (f'<section class="card"><h2>Indicators of compromise</h2>'
                    f'<p class="hint">Defanged for safe pasting into tickets and blocklist requests.</p>'
                    f'<textarea readonly rows="{min(len(lines), 18)}">{e(chr(10).join(lines).strip())}'
                    f'</textarea></section>')

    url_rows = ""
    for u in r.urls:
        flags = "".join(f'<li class="f-{s}">{e(m)}</li>' for s, m in u.flags)
        flags += "".join(f"<li>{e(a)}: {e(b)} ({e(d)})</li>" for a, b, d in u.reputation)
        anchor = f'<div class="detail">Link text: “{e(u.anchor_text)}”</div>' if u.anchor_text else ""
        url_rows += (f'<tr><td class="url">{e(defang(u.url))}{anchor}'
                     f'{f"<ul class=flags>{flags}</ul>" if flags else ""}</td></tr>')
    urls_html = (f'<section class="card"><h2>URLs ({len(r.urls)}, defanged)</h2>'
                 f'<table>{url_rows}</table></section>') if r.urls else ""

    att_html = ""
    if r.attachments:
        rows = "".join(f'<tr><td class="url">{e(a["filename"])}<div class="detail">sha256 '
                       f'{e(a["sha256"])}</div></td><td>{e(a["content_type"])}</td>'
                       f'<td>{a["size"]:,} B</td></tr>' for a in r.attachments)
        att_html = f'<section class="card"><h2>Attachments</h2><table>{rows}</table></section>'

    hops_html = ""
    if p.hops:
        rows = "".join(
            f'<tr><td>{i}</td><td class="url">{e(h.from_host)}</td><td class="url">{e(h.ip)}</td>'
            f'<td class="url">{e(h.by_host)}</td><td>{e(h.timestamp.strftime("%Y-%m-%d %H:%M:%S %z") if h.timestamp else "")}</td>'
            f'<td>{"" if h.delay_s is None else f"+{h.delay_s}s"}</td></tr>'
            for i, h in enumerate(p.hops, 1))
        hops_html = (f'<section class="card"><h2>Received chain (oldest first)</h2><div class="table-wrap">'
                     f'<table><tr><th>#</th><th>From</th><th>IP</th><th>By</th><th>Time</th><th>Delay</th></tr>'
                     f'{rows}</table></div></section>')

    providers = ", ".join(r.providers) if r.providers else "offline heuristics only"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailSleuth Report</title><style>{CSS}</style></head>
<body><main style="--vc:{VERDICT_CSS[r.verdict]}">
<header><div class="brand">MAILSLEUTH</div><div class="src">{e(r.source)}</div></header>
<section class="card verdict"><div class="vhead"><h1>{e(r.verdict)}</h1>
<div class="meter"><div class="bar"><span style="width:{r.score}%"></span></div>
<small>Risk score {r.score}/100 · {len(r.findings)} findings · {len(r.urls)} URLs</small></div></div>
<p class="summary">{e(r.summary)}</p>{breakdown_html}</section>
<section class="card"><h2>Email authentication</h2><div class="auth">{auth_html}</div></section>
<section class="card"><h2>Findings</h2>{findings_html}</section>
{ioc_html}
<section class="card"><h2>Headers</h2><dl>{headers_html}</dl></section>
{urls_html}{att_html}{hops_html}
<footer>Generated {datetime.now().strftime("%Y-%m-%d %H:%M")} · Reputation: {e(providers)}</footer>
</main></body></html>"""
