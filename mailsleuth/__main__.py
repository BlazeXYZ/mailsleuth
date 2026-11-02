"""Command-line entry point: python -m mailsleuth <file.eml> [options]"""

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .report import to_html, to_json, to_terminal


def collect_inputs(paths):
    for raw in paths:
        if raw == "-":
            yield "<stdin>", sys.stdin.buffer.read()
            continue
        path = Path(raw)
        files = sorted(f for f in path.iterdir() if f.suffix.lower() in (".eml", ".txt")) \
            if path.is_dir() else [path]
        for f in files:
            yield f.as_posix(), f.read_bytes()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["serve"]:
        from . import web
        return web.main(argv[1:])

    ap = argparse.ArgumentParser(
        prog="mailsleuth",
        description="Analyze email headers for phishing indicators (SPF/DKIM/DMARC, "
                    "sender spoofing, lookalike domains, malicious links).",
        epilog="Run 'mailsleuth serve' to start the drag-and-drop web UI.")
    ap.add_argument("inputs", nargs="+", help=".eml files, folders of .eml files, or - for stdin")
    ap.add_argument("--html", metavar="PATH",
                    help="write an HTML report (a folder when analyzing several emails)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the text report")
    ap.add_argument("--online", action="store_true",
                    help="check URLs against VirusTotal / URLhaus (needs VT_API_KEY and/or URLHAUS_AUTH_KEY)")
    ap.add_argument("--max-urls", type=int, default=10, help="cap on URLs sent for reputation lookups")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--version", action="version", version=f"mailsleuth {__version__}")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if args.online and not (os.environ.get("VT_API_KEY") or os.environ.get("URLHAUS_AUTH_KEY")):
        print("warning: --online set but neither VT_API_KEY nor URLHAUS_AUTH_KEY is defined; "
              "running offline.", file=sys.stderr)

    reports = []
    try:
        for source, raw in collect_inputs(args.inputs):
            try:
                reports.append(analyze(raw, source, args.online, args.max_urls))
            except ValueError as e:
                print(f"skipping {source}: {e}", file=sys.stderr)
    except OSError as e:
        ap.error(str(e))
    if not reports:
        ap.error("no analyzable emails found")

    if args.json:
        print(to_json(reports))
    else:
        if os.name == "nt":
            os.system("")  # enables ANSI escape handling in the Windows console
        color = not args.no_color and (sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR")))
        print("\n\n".join(to_terminal(r, color) for r in reports))

    if args.html:
        out = Path(args.html)
        if len(reports) == 1 and out.suffix.lower() in (".html", ".htm"):
            targets = [(reports[0], out)]
        else:
            out.mkdir(parents=True, exist_ok=True)
            targets = [(r, out / (Path(r.source).stem + ".html")) for r in reports]
        for r, target in targets:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(to_html(r), encoding="utf-8")
            print(f"HTML report written to {target}", file=sys.stderr)


if __name__ == "__main__":
    main()
