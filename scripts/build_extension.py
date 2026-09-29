"""Copy the shared engine into the browser extension and package it.

    python scripts/build_extension.py          copy docs/{rules,promptlink,page}.js into extension/lib/
    python scripts/build_extension.py --zip    also write dist/promptlink-extension-<version>.zip

The extension uses exactly the same generated rules and engine as the web
checker; tests/test_extension.py fails if the copies are out of date.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT = os.path.join(ROOT, "extension")
SHARED = ("rules.js", "promptlink.js", "page.js")


def copy() -> None:
    os.makedirs(os.path.join(EXT, "lib"), exist_ok=True)
    for name in SHARED:
        shutil.copyfile(os.path.join(ROOT, "docs", name), os.path.join(EXT, "lib", name))


def package() -> str:
    version = json.load(open(os.path.join(EXT, "manifest.json")))["version"]
    os.makedirs(os.path.join(ROOT, "dist"), exist_ok=True)
    out = os.path.join(ROOT, "dist", f"promptlink-extension-{version}.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for base, _, files in os.walk(EXT):
            for f in sorted(files):
                full = os.path.join(base, f)
                z.write(full, os.path.relpath(full, EXT))
    return out


if __name__ == "__main__":
    copy()
    print("copied shared engine into extension/lib/")
    if "--zip" in sys.argv:
        print("wrote", os.path.relpath(package(), ROOT))
