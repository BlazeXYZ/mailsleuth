"""Optional URL reputation lookups (VirusTotal, URLhaus).

Only runs with --online, and only for providers whose API key is set:
  VT_API_KEY        https://www.virustotal.com/gui/my-apikey
  URLHAUS_AUTH_KEY  https://auth.abuse.ch/
"""

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 10


def vt_url_id(url):
    """VirusTotal v3 identifies a URL by its unpadded urlsafe base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _request(req):
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def check_virustotal(url, api_key):
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/urls/{vt_url_id(url)}",
        headers={"x-apikey": api_key},
    )
    try:
        data = _request(req)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "unknown", "Not previously scanned by VirusTotal"
        return "error", f"HTTP {e.code}"
    stats = data["data"]["attributes"]["last_analysis_stats"]
    bad, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(stats.values())
    detail = f"{bad} malicious / {sus} suspicious of {total} engines"
    if bad >= 2:
        return "malicious", detail
    if bad or sus:
        return "suspicious", detail
    return "clean", detail


def check_urlhaus(url, auth_key):
    req = urllib.request.Request(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data=urllib.parse.urlencode({"url": url}).encode(),
        headers={"Auth-Key": auth_key},
    )
    data = _request(req)
    status = data.get("query_status")
    if status == "no_results":
        return "unknown", "Not listed in URLhaus"
    if status != "ok":
        return "error", str(status)
    threat = data.get("threat") or "malware distribution"
    return "malicious", f"Listed in URLhaus ({threat}, status: {data.get('url_status', '?')})"


def enrich(urls, max_urls=10):
    """Attach reputation verdicts to ExtractedURL objects. Returns the providers used."""
    providers = []
    if os.environ.get("VT_API_KEY"):
        providers.append(("VirusTotal", check_virustotal, os.environ["VT_API_KEY"]))
    if os.environ.get("URLHAUS_AUTH_KEY"):
        providers.append(("URLhaus", check_urlhaus, os.environ["URLHAUS_AUTH_KEY"]))

    exhausted = set()
    for u in urls[:max_urls]:
        for name, check, key in providers:
            if name in exhausted:
                u.reputation.append((name, "skipped", "Rate limit reached earlier in this run"))
                continue
            try:
                verdict, detail = check(u.url, key)
            except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
                verdict, detail = "error", str(e)
            if detail == "HTTP 429":
                # Free VirusTotal keys allow 4 requests/minute. Stop asking instead of
                # hammering the API or silently sleeping for minutes.
                exhausted.add(name)
                verdict, detail = "skipped", "Rate limited (HTTP 429)"
            u.reputation.append((name, verdict, detail))
    return [name for name, _, _ in providers]
