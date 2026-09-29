"""Turn scan results (JSONL from research/scan.py) into an honest summary.

    python research/summarize.py results.jsonl > summary.md            counts only (safe to publish)
    python research/summarize.py results.jsonl --details > details.json  flagged sites and text (review first)

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


def details(sites) -> dict:
    """Everything needed to review findings by hand. Names sites, so it is not published."""
    out = {"links": [], "content": [], "llms_txt": [], "templates": []}
    templates = defaultdict(lambda: {"sites": set(), "verdicts": Counter()})
    for s in sites:
        for p in s.get("pages", []):
            for link in p.get("ai_links", []):
                if link["prompt"]:
                    t = templates[normalise(link["prompt"])]
                    t["sites"].add(s["site"])
                    t["verdicts"][link["verdict"]] += 1
                if link["verdict"] in FLAGGED:
                    out["links"].append({"site": s["site"], "page": p["url"], **link})
            for f in (p.get("content") or {}).get("findings", []):
                out["content"].append({"site": s["site"], "page": p["url"], **f})
        for f in (s.get("llms_txt") or {}).get("findings", []):
            out["llms_txt"].append({"site": s["site"], **f})
    out["templates"] = [{"prompt": k, "sites": sorted(v["sites"]), "verdicts": dict(v["verdicts"])}
                        for k, v in sorted(templates.items(), key=lambda kv: -len(kv[1]["sites"]))[:200]]
    return out


def main(path: str, want_details: bool = False) -> int:
    sites = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    if want_details:
        print(json.dumps(details(sites), ensure_ascii=False, indent=1))
        return 0
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
    print(f"Distinct prompt templates: **{len(templates)}** (text is in the review file, not published here)\n")

    content_sites, content_danger, where, how = set(), set(), Counter(), Counter()
    for s in ok:
        for p in s["pages"]:
            for f in (p.get("content") or {}).get("findings", []):
                content_sites.add(s["site"])
                if f["verdict"] == "DANGEROUS":
                    content_danger.add(s["site"])
                where[f["where"]] += 1
                how[f["how"]] += 1
    llms = [s for s in ok if "llms_txt" in s]
    llms_flag = [s for s in llms if s["llms_txt"]["findings"]]
    either = content_sites | flagged
    print("## Instructions aimed at AI inside page content\n")
    print(f"- Sites where a page speaks to AI and gives it orders: **{len(content_sites)}** ({pct(len(content_sites), r)} of reachable sites)")
    print(f"- Of those, hidden from visitors and rated dangerous: **{len(content_danger)}** ({pct(len(content_danger), r)} of reachable sites)")
    if where:
        print("- Where it was found: " + ", ".join(f"{k} {v}" for k, v in where.most_common()))
        print("- How it was hidden: " + ", ".join(f"{k or 'not hidden'} {v}" for k, v in how.most_common(8)))
    print(f"- Sites publishing an llms.txt file: **{len(llms)}** ({pct(len(llms), r)}); with orders in it: **{len(llms_flag)}**\n")
    print("## Either kind\n")
    print(f"- Sites with a flagged AI link **or** flagged page content: **{len(either)}** ({pct(len(either), r)} of reachable sites)\n")
    print("_Unreviewed automatic counts. Flagged items are checked by hand before any site is named, "
          "and the rules miss reworded or script-injected text, so real numbers may be higher._")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], "--details" in sys.argv))
