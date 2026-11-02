"""Local drag-and-drop web UI: python -m mailsleuth serve

Binds to 127.0.0.1 only. Emails are analyzed in memory and never stored.
"""

import argparse
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .analyzer import analyze
from .report import to_html

MAX_BYTES = 10 * 1024 * 1024
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"

INDEX = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailSleuth</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5d6673;--line:#d9dde3;--accent:#6d5efc;
--high:#d7263d;--medium:#d98a00;--ok:#1a9a5a;--chip:#eef0f3;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f13;--card:#151920;--ink:#e6e9ee;--muted:#8b95a3;
--line:#2a313c;--accent:#8b7fff;--high:#ff5468;--medium:#ffb020;--ok:#38d68a;--chip:#1e242d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 48px}
h1{font-family:var(--mono);font-size:20px;letter-spacing:.06em;margin:0}
.tag{color:var(--muted);margin:4px 0 24px}
#drop{display:block;border:2px dashed var(--line);border-radius:14px;padding:40px 16px;text-align:center;background:var(--card);
cursor:pointer;transition:border-color .15s,background .15s}
#drop.over{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,var(--card))}
#drop b{display:block;font-size:18px;margin-bottom:4px}#drop span{color:var(--muted)}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-top:16px}
textarea{width:100%;min-height:110px;margin-top:16px;background:var(--card);color:var(--ink);border:1px solid var(--line);
border-radius:10px;padding:12px;font:13px/1.5 var(--mono);resize:vertical}
button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:8px;padding:7px 14px;cursor:pointer}
button:hover{border-color:var(--accent)}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.muted{color:var(--muted);font-size:13px}
#result{display:none;margin-top:28px}
#bar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.verdict{font-family:var(--mono);font-weight:700;padding:4px 10px;border-radius:6px;color:#fff}
iframe{width:100%;height:80vh;border:1px solid var(--line);border-radius:14px;background:var(--bg)}
#err{color:var(--high);margin-top:12px}
</style></head><body><main>
<h1>MAILSLEUTH</h1>
<p class="tag">Phishing email triage. Drop an <code>.eml</code> file or paste raw headers. Analysis runs locally; nothing is stored.</p>
<label id="drop"><input type="file" id="file" accept=".eml,.txt,message/rfc822" hidden>
<b>Drop an email here</b><span>or click to choose a file</span></label>
<textarea id="paste" placeholder="…or paste raw headers / full source (Gmail: ⋮ → Show original)"></textarea>
<div class="row"><button class="primary" id="go">Analyze pasted text</button>
<span class="muted" id="samplesLabel"></span><span id="samples" class="row" style="margin:0"></span></div>
<div id="err"></div>
<section id="result"><div id="bar"><span class="verdict" id="verdict"></span><span id="score" class="muted"></span>
<span style="flex:1"></span><button id="download">Download report</button></div>
<iframe id="frame" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" title="Analysis report"></iframe></section>
</main>
<script>
const $ = id => document.getElementById(id);
const colors = {"LIKELY PHISHING":"var(--high)","SUSPICIOUS":"var(--medium)","LIKELY LEGITIMATE":"var(--ok)"};
let lastReport = null;

async function send(url, body, name, scroll = true) {
  $("err").textContent = "";
  try {
    const res = await fetch(url + (name ? "?name=" + encodeURIComponent(name) : ""), {method: "POST", body});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    lastReport = data;
    $("verdict").textContent = data.verdict;
    $("verdict").style.background = colors[data.verdict];
    $("score").textContent = `Risk ${data.score}/100 · ${data.source}`;
    $("frame").srcdoc = data.html;
    $("result").style.display = "block";
    if (scroll) $("result").scrollIntoView({behavior: "smooth"});
  } catch (e) { $("err").textContent = "Analysis failed: " + e.message; }
}

const drop = $("drop");
["dragenter","dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) send("/analyze", f, f.name); });
$("file").addEventListener("change", e => { const f = e.target.files[0]; if (f) send("/analyze", f, f.name); });
$("go").addEventListener("click", () => {
  const text = $("paste").value.trim();
  if (text) send("/analyze", new Blob([text.replace(/\r?\n/g, "\r\n")]), "pasted headers");
});
$("download").addEventListener("click", () => {
  if (!lastReport) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([lastReport.html], {type: "text/html"}));
  a.download = lastReport.source.replace(/\.[^.]+$/, "").replace(/[^\w.-]+/g, "_") + "-report.html";
  a.click();
});
fetch("/samples").then(r => r.json()).then(names => {
  // Deep link for demos: /?sample=02_credential_phish.eml runs a sample on load.
  const wanted = new URLSearchParams(location.search).get("sample");
  if (wanted && names.includes(wanted)) send("/sample/" + encodeURIComponent(wanted), null, null, false);
  if (!names.length) return;
  $("samplesLabel").textContent = "Try a sample:";
  names.forEach(n => {
    const b = document.createElement("button");
    b.textContent = n.replace(/^\d+_/, "").replace(/\.eml$/, "").replace(/_/g, " ");
    b.onclick = () => send("/sample/" + encodeURIComponent(n), null);
    $("samples").appendChild(b);
  });
});
</script></body></html>"""


def sample_names():
    return sorted(p.name for p in SAMPLES_DIR.glob("*.eml")) if SAMPLES_DIR.is_dir() else []


def result_payload(raw, source):
    r = analyze(raw, source)
    return {"source": source, "verdict": r.verdict, "score": r.score,
            "summary": r.summary, "html": to_html(r)}


class Handler(BaseHTTPRequestHandler):
    server_version = "MailSleuth"

    def _send(self, status, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj), "application/json")

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, INDEX, "text/html; charset=utf-8")
        elif self.path == "/samples":
            self._json(200, sample_names())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path, _, query = self.path.partition("?")
        if path.startswith("/sample/"):
            name = unquote(path[len("/sample/"):])
            if name not in sample_names():  # whitelist: no path traversal
                return self._json(404, {"error": "unknown sample"})
            return self._json(200, result_payload((SAMPLES_DIR / name).read_bytes(), name))

        if path != "/analyze":
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 < length <= MAX_BYTES:
            return self._json(413 if length else 400, {"error": "send 1 byte to 10 MB of email source"})
        name = unquote(query[5:]) if query.startswith("name=") else "upload.eml"
        try:
            self._json(200, result_payload(self.rfile.read(length), name[:200]))
        except Exception as e:  # malformed input should never kill the server
            self._json(422, {"error": f"could not parse email: {e}"})

    def log_message(self, fmt, *args):
        pass  # keep the console quiet; nothing about emails is logged


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mailsleuth serve", description="Run the local web UI.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    args = ap.parse_args(argv)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"MailSleuth web UI running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
