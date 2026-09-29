"""Run the AI review over a finished scan (results.jsonl from scan.py).

    python research/ai_review.py results.jsonl --provider ollama --model qwen2.5:3b \
        --out ai_review.jsonl --max-minutes 120

Reviews every distinct pre-filled link prompt, then every distinct candidate
page text, until the time budget runs out. Link prompts go first because they
are few and the documented attack. Writes one line per reviewed item, keyed
by site, so summarize.py and review.py can report AI-only finds separately.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from promptlink.judge import make_reviewer  # noqa: E402
from promptlink.page import AI_STRICT, normalise  # noqa: E402
import re  # noqa: E402

STRICT = re.compile(r"\b" + AI_STRICT + r"\b", re.I)


def collect(path):
    links, pages = {}, {}
    for line in open(path, encoding="utf-8"):
        s = json.loads(line)
        for p in s.get("pages", []):
            for l in p.get("ai_links", []):
                if l.get("prompt"):
                    key = normalise(l["prompt"])[:500]
                    links.setdefault(key, {"kind": "link", "text": l["prompt"], "rules": l["verdict"], "sites": set()})
                    links[key]["sites"].add(s["site"])
            for c in p.get("candidates", []):
                key = normalise(c["text"])[:500]
                item = pages.setdefault(key, {"kind": "page", "text": c["text"], "where": c["where"], "how": c["how"],
                                              "sites": set()})
                item["sites"].add(s["site"])
    # Hidden text that names an AI first, then other hidden text, then the rest.
    ranked = sorted(pages.values(), key=lambda i: (i["where"] == "visible", not STRICT.search(i["text"])))
    return list(links.values()) + ranked


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--provider", default="ollama")
    ap.add_argument("--model")
    ap.add_argument("--out", default="ai_review.jsonl")
    ap.add_argument("--max-minutes", type=float, default=120)
    args = ap.parse_args(argv)

    reviewer = make_reviewer(args.provider, args.model)
    items = collect(args.results)
    print(f"{len(items)} distinct items to review with {reviewer.model}", file=sys.stderr)
    deadline = time.time() + args.max_minutes * 60
    done = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for it in items:
            if time.time() > deadline:
                break
            where = f"{it.get('where')} ({it.get('how')})" if it["kind"] == "page" else ""
            j = reviewer.judge(it["text"], it["kind"], where)
            out.write(json.dumps({**it, "sites": sorted(it["sites"]), "ai": j.to_dict(), "ai_flags": j.raises(it["kind"])},
                                 ensure_ascii=False) + "\n")
            done += 1
            if done % 50 == 0:
                print(f"{done}/{len(items)}", file=sys.stderr, flush=True)
    print(f"reviewed {done} of {len(items)} items", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
