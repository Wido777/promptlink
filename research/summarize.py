"""Turn scan results (JSONL from research/scan.py) into an honest summary.

    python research/summarize.py results.jsonl > summary.md

Every percentage states its denominator. "Flagged" means promptlink rated the
link SUSPICIOUS or DANGEROUS; rule-based detection misses reworded prompts,
so flagged counts are a lower bound, and flagged prompts should be checked
by hand before being reported.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict

FLAGGED = {"SUSPICIOUS", "DANGEROUS"}
URL = re.compile(r"https?://\S+|www\.\S+")


def normalise(prompt: str) -> str:
    """Group prompts that differ only by the page URL they point at."""
    return re.sub(r"\s+", " ", URL.sub("<URL>", prompt or "")).strip()[:300]


def pct(n: int, d: int) -> str:
    return f"{n / d:.1%}" if d else "n/a"


def main(path: str) -> int:
    sites = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    status = Counter(s["status"].split(":")[0] for s in sites)
    ok = [s for s in sites if s["status"] == "ok"]
    pages = sum(len(s["pages"]) for s in ok)

    with_ai, with_prompt, flagged, dangerous = set(), set(), set(), set()
    templates = defaultdict(lambda: {"sites": set(), "verdict": Counter(), "example": ""})
    assistants = Counter()
    for s in ok:
        for p in s["pages"]:
            for link in p["ai_links"]:
                with_ai.add(s["site"])
                if not link["prompt"]:
                    continue
                with_prompt.add(s["site"])
                assistants[link["assistant"]] += 1
                t = templates[normalise(link["prompt"])]
                t["sites"].add(s["site"])
                t["verdict"][link["verdict"]] += 1
                t["example"] = t["example"] or link["prompt"][:300]
                if link["verdict"] in FLAGGED:
                    flagged.add(s["site"])
                if link["verdict"] == "DANGEROUS":
                    dangerous.add(s["site"])

    n, r = len(sites), len(ok)
    print(f"# promptlink scan summary\n")
    print(f"- Sites attempted: **{n}**")
    print(f"- Reachable and allowed by robots.txt: **{r}** ({pct(r, n)})")
    for k, v in sorted(status.items(), key=lambda kv: -kv[1]):
        if k != "ok":
            print(f"  - {k}: {v}")
    print(f"- Pages read: **{pages}** (homepage plus up to a few article pages per site)\n")
    print("## AI-assistant links\n")
    print(f"- Sites with any AI-assistant link: **{len(with_ai)}** ({pct(len(with_ai), r)} of reachable sites)")
    print(f"- Sites with an AI link that carries a pre-filled prompt: **{len(with_prompt)}** ({pct(len(with_prompt), r)} of reachable sites)")
    print(f"- Of those, flagged by promptlink (suspicious or dangerous): **{len(flagged)}** ({pct(len(flagged), len(with_prompt))})")
    print(f"- Of those, rated dangerous: **{len(dangerous)}** ({pct(len(dangerous), len(with_prompt))})\n")
    if assistants:
        print("Assistants targeted (links with a prompt): " + ", ".join(f"{a} {c}" for a, c in assistants.most_common()) + "\n")
    print("## Prompt templates, most widespread first\n")
    print("| Sites | Verdicts | Prompt (URLs replaced with <URL>) |\n|---|---|---|")
    ranked = sorted(templates.items(), key=lambda kv: -len(kv[1]["sites"]))
    for text, t in ranked[:25]:
        v = ", ".join(f"{k.lower()} {c}" for k, c in t["verdict"].most_common())
        print(f"| {len(t['sites'])} | {v} | {text.replace('|', '/')} |")
    print("\n_Flagged counts are a lower bound: the rules miss reworded prompts. "
          "Check flagged and unflagged templates by hand before publishing._")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
