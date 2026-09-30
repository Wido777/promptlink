"""Emit part of a text file as GitHub Actions notice annotations, which can be
read back through the API. GitHub keeps at most 10 notices per step.

    python research/annotate.py review.md <first chunk> <how many>
"""

import os
import sys

CHUNK = 2500   # GitHub truncates notice messages at about 4 KB (bytes, so non-Latin text needs room)

text = open(sys.argv[1], encoding="utf-8").read()
first, count = int(sys.argv[2]), int(sys.argv[3])
chunks = [text[i:i + CHUNK] for i in range(0, len(text), CHUNK)]
for n in range(first, min(first + count, len(chunks))):
    esc = chunks[n].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    title = os.environ.get("ANNOTATION_TITLE", "review part")
    print(f"::notice title={title} {n + 1:02d}/{len(chunks)}::{esc}")
