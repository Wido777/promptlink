"""The browser extension ships the same engine as the web checker."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ExtensionUpToDate(unittest.TestCase):
    def test_engine_copies_match(self):
        for name in ("rules.js", "promptlink.js", "page.js"):
            with open(os.path.join(ROOT, "docs", name), encoding="utf-8") as a, \
                 open(os.path.join(ROOT, "extension", "lib", name), encoding="utf-8") as b:
                self.assertEqual(a.read(), b.read(), f"extension/lib/{name} is stale: run python scripts/build_extension.py")

    def test_manifest(self):
        with open(os.path.join(ROOT, "extension", "manifest.json"), encoding="utf-8") as fh:
            m = json.load(fh)
        from promptlink import __version__
        self.assertEqual(m["version"], __version__)
        self.assertEqual(m["permissions"], ["activeTab"])          # no storage, no network, no tabs
        for f in m["content_scripts"][0]["js"] + [m["background"]["service_worker"], m["action"]["default_popup"]]:
            self.assertTrue(os.path.exists(os.path.join(ROOT, "extension", f)), f)


if __name__ == "__main__":
    unittest.main()
