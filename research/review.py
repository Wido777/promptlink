"""Print every flagged item from a scan, with sites anonymised, for review.

    python research/review.py results.jsonl > review.md

Judging whether a flag is a real hidden instruction or a false alarm needs
the text and where it was hidden, not the site's name. So sites become
"site 12", and domain names and URLs inside the text are replaced, which
keeps this safe to show in a public run before anything is confirmed.
"""

from __future__ import annotations

import json
import re
import sys

URL = re.compile(r"https?://\S+|www\.\S+", re.I)
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|ai|app|dev|info|biz|shop|store|site|online|xyz|"
                    r"[a-z]{2})\b", re.I)


def scrub(text: str, site: str) -> str:
    bare = re.sub(r"^https?://|^www\.|/.*$", "", site).lower()
    stem = bare.split(".")[0]
    text = URL.sub("<url>", text or "")
    text = DOMAIN.sub("<domain>", text)
    if len(stem) >= 4:
        text = re.sub(re.escape(stem), "<site>", text, flags=re.I)
    return re.sub(r"\s+", " ", text).strip()


def main(path: str, ai_path: str | None = None) -> int:
    sites = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    ids = {s["site"]: i for i, s in enumerate(sorted(sites, key=lambda s: s["site"]), 1)}
    rows = []
    if ai_path:
        for r in (json.loads(l) for l in open(ai_path, encoding="utf-8") if l.strip()):
            if r["ai_flags"]:
                site = r["sites"][0]
                where = r["kind"] if r["kind"] == "link" else f"{r['where']} / {r['how']}"
                rows.append((f"AI {r['kind']}", ids.get(site, 0), f"AI {r['ai']['category']} {r['ai']['confidence']:.2f}",
                             where + f" / {len(r['sites'])} site(s)", scrub(r["ai"]["reason"], site)[:160], scrub(r["text"], site)))
    for s in sites:
        sid = ids[s["site"]]
        for p in s.get("pages", []):
            for f in (p.get("content") or {}).get("findings", []):
                rows.append(("content", sid, f["verdict"], f"{f['where']} / {f['how']} / <{f['tag']}>",
                             ",".join(f["rules"]), scrub(f["text"], s["site"])))
            for l in p.get("ai_links", []):
                if l.get("prompt"):
                    rows.append(("link", sid, l["verdict"], l["assistant"], ",".join(l["rules"]),
                                 scrub(l["prompt"], s["site"])))
        for f in (s.get("llms_txt") or {}).get("findings", []):
            rows.append(("llms.txt", sid, f["verdict"], f["how"], ",".join(f["rules"]), scrub(f["text"], s["site"])))

    order = {"DANGEROUS": 0, "SUSPICIOUS": 1, "LOOKS_SAFE": 2}
    rows.sort(key=lambda r: (not r[0].startswith("AI"), r[0] != "content", order.get(r[2], 3), r[1]))
    for kind, sid, verdict, where, rules, text in rows:
        print(f"[{kind}] site {sid} | {verdict} | {where} | {rules}\n  {text[:400]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[sys.argv.index("--ai") + 1] if "--ai" in sys.argv else None))
