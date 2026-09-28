"""Command-line interface for promptlink."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .detector import check_url, scan_html

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

    p_page = sub.add_parser("page", help="find and check every assistant link in a saved HTML page or email (.html/.eml/.txt)")
    p_page.add_argument("file", help="path to the file, or - for stdin")
    p_page.add_argument("--json", action="store_true", help="print machine-readable JSON")

    args = parser.parse_args(argv)
    colour = _use_colour(sys.stdout) and not args.json

    if args.command == "check":
        urls = args.urls or [line.strip() for line in sys.stdin if line.strip()]
        if not urls:
            parser.error("give at least one link, or pipe links in")
        reports = [check_url(u) for u in urls]
    else:
        if args.file == "-":
            content = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        reports = scan_html(content)
        if not reports and not args.json:
            print("No AI-assistant links found in this file.")
            return 0

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        for rep in reports:
            print_report(rep, colour)
        if len(reports) > 1:
            counts = {}
            for rep in reports:
                counts[rep.verdict] = counts.get(rep.verdict, 0) + 1
            print("summary: " + ", ".join(f"{k.lower()}={v}" for k, v in sorted(counts.items())))

    return max((EXIT_CODES.get(r.verdict, 0) for r in reports), default=0)


if __name__ == "__main__":
    sys.exit(main())
