"""Command-line interface for promptlink."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .detector import URL_IN_TEXT, check_url, scan_html
from .page import WHERE_TEXT, scan_page_content

COLOURS = {
    "DANGEROUS": "\033[1;31m",
    "SUSPICIOUS": "\033[1;33m",
    "LOOKS_SAFE": "\033[1;32m",
    "NO_PROMPT": "\033[1;36m",
    "NOT_ASSISTANT_LINK": "\033[2m",
}
RESET = "\033[0m"

LABELS = {
    "DANGEROUS": "DANGEROUS  - do not open this link",
    "SUSPICIOUS": "SUSPICIOUS - read the prompt below before opening",
    "LOOKS_SAFE": "LOOKS SAFE - no manipulation patterns found",
    "NO_PROMPT": "NO PROMPT  - opens an assistant with nothing pre-filled",
    "NOT_ASSISTANT_LINK": "NOT AN AI-ASSISTANT LINK",
}

EXIT_CODES = {"DANGEROUS": 2, "SUSPICIOUS": 1}


def _use_colour(stream) -> bool:
    return stream.isatty() and os.environ.get("NO_COLOR") is None


def print_report(rep, colour: bool) -> None:
    c = COLOURS.get(rep.verdict, "") if colour else ""
    r = RESET if colour else ""
    print(f"{c}{LABELS[rep.verdict]}{r}")
    print(f"  link:      {rep.url[:120]}{'…' if len(rep.url) > 120 else ''}")
    if rep.assistant:
        print(f"  opens:     {rep.assistant}")
    for i, wrapper in enumerate(rep.unwrapped_from, 1):
        print(f"  wrapper {i}: {wrapper[:100]}")
    if rep.prompt is not None:
        print(f"  prompt ({rep.param}=):")
        shown = rep.prompt if len(rep.prompt) <= 500 else rep.prompt[:500] + " …[truncated]"
        for line in shown.splitlines() or [""]:
            print(f"    | {line}")
    if rep.findings:
        print(f"  findings (score {rep.score}):")
        for f in rep.findings:
            print(f"    [{f.rule}] {f.description}")
            print(f"        {f.evidence}")
    for note in rep.notes:
        print(f"  note: {note}")
    print()


CONTENT_LABELS = {
    "DANGEROUS": "DANGEROUS  - this page hides instructions aimed at AI",
    "SUSPICIOUS": "SUSPICIOUS - this page talks to AI in a way worth reading",
    "LOOKS_SAFE": "LOOKS SAFE - no hidden instructions for AI found in the page text",
}


def fetch_page(url: str) -> str:
    """Download one page (only when the user asks for it with a URL or --follow)."""
    from urllib.request import Request, urlopen
    req = Request(url, headers={"User-Agent": f"promptlink/{__version__} (+https://github.com/Wido777/promptlink)",
                                "Accept": "text/html,application/xhtml+xml,text/plain"})
    with urlopen(req, timeout=15) as r:
        raw = r.read(5_000_000)
        return raw.decode(r.headers.get_content_charset() or "utf-8", errors="replace")


def print_content(rep, source: str, colour: bool) -> None:
    c = COLOURS.get(rep.verdict, "") if colour else ""
    r = RESET if colour else ""
    print(f"{c}{CONTENT_LABELS[rep.verdict]}{r}")
    print(f"  page:      {source[:120]}")
    print(f"  read {rep.chunks} text blocks, {rep.hidden_chunks} of them hidden from visitors")
    for f in rep.findings[:10]:
        print(f"  [{f.verdict.lower()}] in {WHERE_TEXT.get(f.where, f.where)}" + (f" ({f.how})" if f.how else ""))
        shown = f.text if len(f.text) <= 300 else f.text[:300] + " …"
        print(f"    | {shown}")
        print("    rules: " + ", ".join(x.rule for x in f.findings))
    if len(rep.findings) > 10:
        print(f"  … and {len(rep.findings) - 10} more")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="promptlink",
        description="Check AI-assistant links (ChatGPT, Copilot, Claude, Perplexity, Grok, ...) "
                    "for hidden prompts that try to poison the assistant's memory. "
                    "Links are never opened.")
    parser.add_argument("--version", action="version", version=f"promptlink {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="check one or more links")
    p_check.add_argument("urls", nargs="*", help="links to check (or pipe them in, one per line)")
    p_check.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p_check.add_argument("--follow", action="store_true",
                         help="also download the page the prompt points to and look for hidden instructions in it")

    p_page = sub.add_parser("page", help="check a web page or email: its AI-assistant links and any hidden "
                                         "instructions aimed at AI in its content")
    p_page.add_argument("file", help="path to a saved .html/.eml/.txt file, - for stdin, or an http(s) URL to download")
    p_page.add_argument("--json", action="store_true", help="print machine-readable JSON")

    args = parser.parse_args(argv)
    colour = _use_colour(sys.stdout) and not args.json

    if args.command == "check":
        urls = args.urls or [line.strip() for line in sys.stdin if line.strip()]
        if not urls:
            parser.error("give at least one link, or pipe links in")
        reports = [check_url(u) for u in urls]
        followed = []
        if args.follow:
            for rep in reports:
                for target in list(dict.fromkeys(URL_IN_TEXT.findall(rep.prompt or "")))[:3]:
                    target = target.rstrip(".,;)")
                    try:
                        followed.append((target, scan_page_content(fetch_page(target if "://" in target else "https://" + target))))
                    except Exception as e:  # noqa: BLE001
                        print(f"could not read {target}: {e}", file=sys.stderr)
    else:
        if args.file == "-":
            content = sys.stdin.read()
        elif args.file.startswith(("http://", "https://")):
            content = fetch_page(args.file)
        else:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        reports = scan_html(content)
        followed = [(args.file, scan_page_content(content))]

    if args.json:
        if args.command == "check" and not args.follow:
            print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
        else:
            print(json.dumps({"links": [r.to_dict() for r in reports],
                              "content": [dict(page=src, **rep.to_dict()) for src, rep in followed]},
                             indent=2, ensure_ascii=False))
    else:
        if args.command == "page" and not reports:
            print("No AI-assistant links found.\n")
        for rep in reports:
            print_report(rep, colour)
        if len(reports) > 1:
            counts = {}
            for rep in reports:
                counts[rep.verdict] = counts.get(rep.verdict, 0) + 1
            print("summary: " + ", ".join(f"{k.lower()}={v}" for k, v in sorted(counts.items())) + "\n")
        for src, rep in followed:
            print_content(rep, src, colour)

    verdicts = [r.verdict for r in reports] + [rep.verdict for _, rep in followed]
    return max((EXIT_CODES.get(v, 0) for v in verdicts), default=0)


if __name__ == "__main__":
    sys.exit(main())
