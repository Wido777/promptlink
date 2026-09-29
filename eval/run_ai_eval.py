"""Score the rules, the AI review, and both combined, on every labelled set.

    python eval/run_ai_eval.py --provider ollama --model qwen2.5:3b --out ai_eval.md

"Flagged" means SUSPICIOUS or DANGEROUS. For the AI alone, flagged means the
model said manipulative with confidence >= judge.RAISE_AT. Combined is what
`promptlink --ai` reports: the rules' verdict, raised by the AI, never lowered.
A reply the tool could not use counts as "not flagged" for the AI and is
reported separately, so errors can't hide.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib.parse import quote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "eval")]

from promptlink import check_url  # noqa: E402
from promptlink.judge import combine, make_reviewer  # noqa: E402
from promptlink.page import Chunk, analyse_chunk  # noqa: E402
import cases  # noqa: E402
import holdout  # noqa: E402
import in_the_wild  # noqa: E402
import pages  # noqa: E402
import real_world  # noqa: E402
import reworded  # noqa: E402
import scan_10k  # noqa: E402
from promptlink.page import extract_chunks  # noqa: E402

FLAGGED = {"SUSPICIOUS", "DANGEROUS"}


def link_items(pairs, name):
    """pairs: (label, prompt, note)"""
    return [{"set": name, "kind": "link", "label": l, "text": p, "note": n} for l, p, n in pairs]


def url_items(rows, name):
    """rows: (label, url, note): the prompt is decoded from the URL."""
    out = []
    for label, url, note in rows:
        rep = check_url(url)
        out.append({"set": name, "kind": "link", "label": label, "text": rep.prompt or "", "note": note, "url": url})
    return out


def build(sets):
    items = []
    if "reworded" in sets:
        items += link_items(reworded.LINKS, "reworded links (unseen)")
        items += [{"set": "reworded page text (unseen)", "kind": "page", "label": l, "text": t, "where": w, "how": h,
                   "note": n} for l, t, w, h, n in reworded.PAGES]
    if "holdout" in sets:
        items += link_items([("malicious", p, n) for p, n in holdout.MALICIOUS] +
                            [("benign", p, n) for p, n in holdout.BENIGN], "held-out links")
    if "real" in sets:
        items += url_items([(c["label"], c["url"], c["source"]) for c in real_world.CASES], "published templates")
    if "wild" in sets:
        items += url_items([(c["label"], c["url"], c["site"]) for c in in_the_wild.CASES], "live sites (2026)")
    if "scan" in sets:
        items += link_items(scan_10k.LINKS, "10k-scan links")
        items += [{"set": "10k-scan page text", "kind": "page", "label": "benign", "text": t, "where": w, "how": h,
                   "note": n} for t, w, h, tag, n in scan_10k.CONTENT]
    if "pages" in sets:
        for label, group in (("malicious", pages.MALICIOUS), ("benign", pages.BENIGN)):
            for html, note in group:
                cs = [c for c in extract_chunks(html) if c.text.strip()]
                # the chunk that matters: the hidden/odd one if any, else the first
                c = next((c for c in cs if c.where != "visible"), cs[0] if cs else Chunk("", "visible"))
                items.append({"set": "self-written pages", "kind": "page", "label": label, "text": c.text,
                              "where": c.where, "how": c.how, "note": note})
    return [i for i in items if i["text"].strip()]


def rules_verdict(item):
    if item["kind"] == "link":
        return check_url("https://chatgpt.com/?q=" + quote(item["text"], safe="")).verdict
    f = analyse_chunk(Chunk(item["text"], item["where"], item.get("how", ""), "div"))
    return f.verdict if f else "LOOKS_SAFE"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="ollama")
    ap.add_argument("--model")
    ap.add_argument("--sets", default="reworded,holdout,real,wild,scan,pages")
    ap.add_argument("--out", default="ai_eval.md")
    ap.add_argument("--jsonl", default="ai_eval.jsonl")
    args = ap.parse_args(argv)

    reviewer = make_reviewer(args.provider, args.model)
    items = build(set(args.sets.split(",")))
    print(f"{len(items)} items, model {reviewer.model}", file=sys.stderr)
    started = time.time()
    with open(args.jsonl, "w", encoding="utf-8") as out:
        for n, it in enumerate(items, 1):
            it["rules"] = rules_verdict(it)
            where = f"{it.get('where')} ({it.get('how')})" if it["kind"] == "page" else ""
            t0 = time.time()
            j = reviewer.judge(it["text"], it["kind"], where)
            it["seconds"] = round(time.time() - t0, 2)
            it["ai"] = j.to_dict()
            it["ai_flags"] = j.flags
            it["combined"] = combine(it["rules"], j)
            out.write(json.dumps(it, ensure_ascii=False) + "\n")
            if n % 20 == 0:
                print(f"{n}/{len(items)}  {time.time() - started:.0f}s", file=sys.stderr, flush=True)
    report(items, reviewer.model, time.time() - started, args.out)


def report(items, model, seconds, path):
    sets = list(dict.fromkeys(i["set"] for i in items))
    lines = [f"# AI review evaluation: {model}\n",
             f"{len(items)} items in {seconds / 60:.1f} min ({seconds / max(len(items), 1):.1f} s per item). "
             "Cells show attacks caught / attacks, then false alarms / harmless items.\n",
             "| Set | Rules | AI alone | Rules + AI | AI errors |", "|---|---|---|---|---|"]
    tot = {k: [0, 0, 0, 0] for k in ("rules", "ai", "combined")}
    errors_total = 0
    for s in sets:
        rows = [i for i in items if i["set"] == s]
        mal = [i for i in rows if i["label"] == "malicious"]
        ben = [i for i in rows if i["label"] == "benign"]
        cells = []
        for key in ("rules", "ai", "combined"):
            hit = (lambda i: i["ai_flags"]) if key == "ai" else (lambda i, k=key: i[k] in FLAGGED)
            tp, fp = sum(map(hit, mal)), sum(map(hit, ben))
            tot[key][0] += tp; tot[key][1] += len(mal); tot[key][2] += fp; tot[key][3] += len(ben)
            cells.append(f"{tp}/{len(mal)} · {fp}/{len(ben)}" if mal else f"– · {fp}/{len(ben)}")
        errs = sum(1 for i in rows if i["ai"]["error"])
        errors_total += errs
        lines.append(f"| {s} | " + " | ".join(cells) + f" | {errs} |")
    lines.append("| **All** | " + " | ".join(f"**{t[0]}/{t[1]} · {t[2]}/{t[3]}**" for t in tot.values())
                 + f" | {errors_total} |\n")
    lines.append("## Attacks missed by rules + AI\n")
    for i in items:
        if i["label"] == "malicious" and i["combined"] not in FLAGGED:
            lines.append(f"- [{i['set']}] {i['note']}: AI said {i['ai']['category']} "
                         f"{i['ai']['confidence']:.2f}{' ERROR ' + i['ai']['error'] if i['ai']['error'] else ''}")
    lines.append("\n## False alarms raised by the AI\n")
    for i in items:
        if i["label"] == "benign" and i["ai_flags"]:
            lines.append(f"- [{i['set']}] {i['note']}: {i['ai']['category']} {i['ai']['confidence']:.2f}: "
                         f"{i['ai']['reason'][:140]}")
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)


if __name__ == "__main__":
    main()
