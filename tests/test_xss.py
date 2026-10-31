"""Reflected-XSS checker + autonomous discovery against the local fixture."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_xss
from orchestrator.core import run_engagement
from orchestrator.scanner import DynamicExecutors
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session

CONFIG = {
    "limits": {"max_iterations": 40, "max_requests": 400, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi", "path-traversal", "xss"],
    "focus": ["idor", "cmdi", "path-traversal", "xss"],
}


class XssTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, name):
        return check_xss(Session(self.base),
                         {"endpoint": endpoint, "parameter": "q", "method": "GET"},
                         Path(self.tmp) / name, CheckContext())

    def test_reflected_unencoded_confirmed(self):
        ev = Path(self.tmp) / "ev"
        res = check_xss(Session(self.base),
                        {"endpoint": "/search", "parameter": "q", "method": "GET"},
                        ev, CheckContext())
        self.assertEqual(res.status, "confirmed")
        self.assertIn("<HB", res.payload)
        self.assertIn("<HB", (ev / "inject-xss.response.http").read_text())

    def test_encoded_output_is_false_positive(self):
        res = self._check("/safe-search", "safe")
        self.assertEqual(res.status, "false-positive")
        self.assertIn("encoded", res.false_positive_reason)

    def test_autonomous_discovers_and_confirms_xss(self):
        t = Path(self.tmp) / "tgt"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        summary = run_engagement(t, execs, mode="auto", objective="Full scan")
        hyps = json.loads((t / "recon" / "hypotheses.json").read_text())
        self.assertIn("XSS", {h["class"] for h in hyps})
        findings = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "XSS" and f["status"] == "confirmed"
                            for f in findings))
        # IDOR + CMDI + PATH-TRAVERSAL + XSS all confirmed from a base URL + creds only.
        self.assertEqual(summary["findings"].get("confirmed"), 4)


if __name__ == "__main__":
    unittest.main()
