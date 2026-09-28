"""Run promptlink over the hand-labelled cases and report honest numbers.

Usage:  python eval/run_eval.py              held-out set (the honest number)
        python eval/run_eval.py --dev        development set (rules were tuned on it)
        python eval/run_eval.py --markdown   table for the README (add --dev for dev set)
"""

import os
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from promptlink import check_url  # noqa: E402
import cases  # noqa: E402
import holdout  # noqa: E402

ASSISTANTS = cases.ASSISTANTS
SET = cases if "--dev" in sys.argv else holdout
MALICIOUS, BENIGN = SET.MALICIOUS, SET.BENIGN

FLAGGED = {"SUSPICIOUS", "DANGEROUS"}


def run():
    rows = []
    for label, group in (("malicious", MALICIOUS), ("benign", BENIGN)):
        for i, (prompt, note) in enumerate(group):
            url = ASSISTANTS[i % len(ASSISTANTS)] + quote(prompt, safe="")
            rep = check_url(url)
            rows.append((label, note, prompt, rep.verdict, rep.score))
    return rows


def main():
    rows = run()
    tp = sum(1 for r in rows if r[0] == "malicious" and r[3] in FLAGGED)
    fn = sum(1 for r in rows if r[0] == "malicious" and r[3] not in FLAGGED)
    fp = sum(1 for r in rows if r[0] == "benign" and r[3] in FLAGGED)
    tn = sum(1 for r in rows if r[0] == "benign" and r[3] not in FLAGGED)
    dangerous_benign = sum(1 for r in rows if r[0] == "benign" and r[3] == "DANGEROUS")
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    if "--markdown" in sys.argv:
        print("| | Flagged | Not flagged |\n|---|---|---|")
        print(f"| Malicious ({tp + fn}) | {tp} | {fn} |")
        print(f"| Benign ({fp + tn}) | {fp} | {tn} |")
        print(f"\nRecall {recall:.0%}, precision {precision:.0%}, "
              f"false-alarm rate {fp / (fp + tn):.0%}, benign links rated DANGEROUS: {dangerous_benign}")
        return

    print("Set:", "development (tuned on - optimistic)" if SET is cases else "held-out (not tuned on)")
    print(f"Malicious caught: {tp}/{tp + fn}  (recall {recall:.0%})")
    print(f"Benign flagged:   {fp}/{fp + tn}  (false-alarm rate {fp / (fp + tn):.0%}, "
          f"{dangerous_benign} rated DANGEROUS)")
    print(f"Precision:        {precision:.0%}\n")
    print("MISSED malicious:")
    for r in rows:
        if r[0] == "malicious" and r[3] not in FLAGGED:
            print(f"  - [{r[1]}] {r[2][:100]}")
    print("\nFALSE ALARMS on benign:")
    for r in rows:
        if r[0] == "benign" and r[3] in FLAGGED:
            print(f"  - [{r[1]}] {r[3]} (score {r[4]}): {r[2][:100]}")


if __name__ == "__main__":
    main()
