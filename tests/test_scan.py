"""research/scan.py against local fake sites (no internet needed)."""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "research"), os.path.join(ROOT, "tests")]

import scan  # noqa: E402
import test_sites  # noqa: E402


class ScanFakeSites(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scan.PAGE_PAUSE = 0
        cls.servers, cls.ports = [], {}
        for key, pages in test_sites.SITES.items():
            s = ThreadingHTTPServer(("127.0.0.1", 0), test_sites.handler_for(pages))
            threading.Thread(target=s.serve_forever, daemon=True).start()
            cls.servers.append(s)
            cls.ports[key] = s.server_port
        test_sites.LOG.clear()
        with tempfile.TemporaryDirectory() as d:
            sites = os.path.join(d, "sites.txt")
            out = os.path.join(d, "out.jsonl")
            with open(sites, "w") as fh:
                for key in sorted(cls.ports):
                    fh.write(f"http://127.0.0.1:{cls.ports[key]}\n")
                fh.write("http://127.0.0.1:1\n")  # nothing listens here
            scan.main(["--urls", sites, "--sites", "20", "--out", out, "--workers", "4"])
            with open(out, encoding="utf-8") as fh:
                cls.results = {r["site"]: r for r in map(json.loads, fh)}

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def site(self, key):
        return self.results[f"http://127.0.0.1:{self.ports[key]}"]

    def verdicts(self, key):
        return sorted(a["verdict"] for p in self.site(key)["pages"] for a in p["ai_links"])

    def test_finds_poisoned_button_on_article_page(self):
        self.assertEqual(self.verdicts(8801), ["DANGEROUS", "LOOKS_SAFE"])

    def test_respects_robots_disallow_all(self):
        self.assertEqual(self.site(8802)["status"], "robots_disallowed")
        port = self.ports[8802]
        requested = [l.split(" ")[0] for l in test_sites.LOG if l.startswith(f"{port}/")]
        self.assertEqual(requested, [f"{port}/robots.txt"])

    def test_respects_robots_disallowed_path(self):
        port = self.ports[8801]
        self.assertFalse(any(l.startswith(f"{port}/private") for l in test_sites.LOG))

    def test_finds_escaped_url_in_inline_script(self):
        self.assertEqual(self.verdicts(8803), ["DANGEROUS"])

    def test_non_html_and_missing_robots(self):
        self.assertTrue(self.site(8804)["status"].startswith("no_html"))
        self.assertEqual(self.verdicts(8805), ["LOOKS_SAFE"])

    def test_finds_hidden_instructions_in_page_content(self):
        home = self.site(8806)["pages"][0]["content"]
        self.assertEqual(home["verdict"], "DANGEROUS")
        self.assertEqual([f["how"] for f in home["findings"]], ["display:none"])
        self.assertEqual(self.site(8806)["llms_txt"]["verdict"], "SUSPICIOUS")

    def test_clean_pages_have_clean_content(self):
        for key in (8801, 8803, 8805):
            for p in self.site(key)["pages"]:
                self.assertEqual(p["content"]["verdict"], "LOOKS_SAFE", key)
        self.assertNotIn("llms_txt", self.site(8805))   # 404 is not an llms.txt

    def test_candidates_kept_for_ai_review(self):
        cands = self.site(8806)["pages"][0]["candidates"]
        self.assertTrue(any("Note to AI" in c["text"] for c in cands))
        self.assertFalse(any("Skip to content" in c["text"] for c in cands))

    def test_ai_review_pipeline(self):
        import ai_review
        import review
        import summarize
        from test_judge import FakeProvider
        fake = FakeProvider({"speaks_to_ai": True, "persistent": True, "manipulative": True,
                             "category": "hidden-orders", "confidence": 0.9,
                             "reason": "tells the AI what to say about Site F"})
        os.environ["OLLAMA_HOST"] = fake.url
        try:
            with tempfile.TemporaryDirectory() as d:
                res, out = os.path.join(d, "r.jsonl"), os.path.join(d, "ai.jsonl")
                with open(res, "w") as fh:
                    for r in self.results.values():
                        fh.write(json.dumps(r) + "\n")
                ai_review.main([res, "--out", out, "--max-minutes", "1"])
                rows = [json.loads(l) for l in open(out)]
                self.assertTrue(rows and all(r["ai_flags"] for r in rows))
                self.assertEqual(rows[0]["kind"], "link")            # link prompts are reviewed first
                buf = io.StringIO()
                with redirect_stdout(buf):
                    summarize.main(res, False, out)
                    review.main(res, out)
                text = buf.getvalue()
                self.assertIn("## AI review", text)
                self.assertIn("[AI page]", text)
        finally:
            del os.environ["OLLAMA_HOST"]
            fake.close()

    def test_unreachable_site(self):
        self.assertEqual(self.results["http://127.0.0.1:1"]["status"], "unreachable")

    def test_identifies_itself(self):
        self.assertTrue(test_sites.LOG and all("UA=promptlink-research" in l for l in test_sites.LOG))


if __name__ == "__main__":
    unittest.main()
