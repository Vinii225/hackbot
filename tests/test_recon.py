"""Tests for autonomous recon: the crawler discovers the surface and generates
hypotheses, and the full loop confirms the vulns WITHOUT anyone handing it the endpoints.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.core import run_engagement
from orchestrator.http_exec import DynamicExecutors
from orchestrator.recon import make_hypotheses, templatize
from tests.fixtures.mock_lab import start_mock_lab
from tools.crawler import crawl_site
from tools.httpx import Session

CONFIG = {
    "limits": {"max_iterations": 30, "max_requests": 300, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi"], "focus": ["idor", "cmdi"],
}


class CrawlerUnitTests(unittest.TestCase):
    def test_templatize(self):
        self.assertEqual(templatize("/api/user/42"), ("/api/user/{id}", [42]))
        self.assertEqual(templatize("/about")[1], [])

    def test_hypotheses_from_fake_crawl(self):
        class C:
            object_ids = {1, 2}
            def endpoint_list(self):
                return [{"path": "/api/user/1", "method": "GET", "params": []},
                        {"path": "/ping", "method": "GET", "params": ["host"]},
                        {"path": "/about", "method": "GET", "params": []}]
        hyps = make_hypotheses(C())
        classes = {(h["class"], h["endpoint"]) for h in hyps}
        self.assertIn(("IDOR", "/api/user/{id}"), classes)
        self.assertIn(("CMDI", "/ping"), classes)


class AutonomousReconTests(unittest.TestCase):
    def setUp(self):
        self.httpd, self.thread, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _target(self):
        t = Path(self.tmp) / "tgt"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        return t

    def test_crawler_discovers_surface(self):
        s = Session(self.base)
        s.post("/login", data={"username": "wiener", "password": "peter"})
        crawl = crawl_site([self.base], s)
        paths = {ep["path"] for ep in crawl.endpoint_list()}
        self.assertIn("/api/user/1", paths)     # discovered via the account link
        self.assertIn("/ping", paths)           # discovered via the form
        # the form's parameter was captured
        ping = next(ep for ep in crawl.endpoint_list() if ep["path"] == "/ping")
        self.assertIn("host", ping["params"])
        self.assertIn("/me", crawl.js_endpoints)  # found in app.js

    def test_full_autonomous_run_confirms_both(self):
        t = self._target()
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        summary = run_engagement(t, execs, mode="auto",
                                 objective="Scan the app for IDOR and command injection")
        # Recon generated the hypotheses itself.
        hyps = json.loads((t / "recon" / "hypotheses.json").read_text())
        classes = {h["class"] for h in hyps}
        self.assertIn("IDOR", classes)
        self.assertIn("CMDI", classes)
        # And both were confirmed end-to-end.
        self.assertEqual(summary["findings"].get("confirmed"), 2)
        self.assertTrue((t / "reports" / "REPORT.md").exists())
        report = (t / "reports" / "REPORT.md").read_text()
        self.assertIn("IDOR", report)
        self.assertIn("CMDI", report)


if __name__ == "__main__":
    unittest.main()
