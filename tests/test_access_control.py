"""Unauthenticated privileged-access checker + autonomous discovery via robots.txt."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_unauth_access
from orchestrator.core import run_engagement
from orchestrator.scanner import DynamicExecutors
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session

CONFIG = {
    "limits": {"max_iterations": 50, "max_requests": 500, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi", "path-traversal", "xss", "access-control"],
    "focus": ["access-control"],
}


class AccessControlTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, name):
        # pass an authenticated session; the checker must still probe anonymously
        auth = Session(self.base)
        auth.post("/login", data={"username": "wiener", "password": "peter"})
        return check_unauth_access(auth, {"endpoint": endpoint, "method": "GET"},
                                   Path(self.tmp) / name, CheckContext())

    def test_unprotected_panel_confirmed(self):
        res = self._check("/admin-panel", "panel")
        self.assertEqual(res.status, "confirmed")
        self.assertIn("no session", res.payload)

    def test_protected_endpoint_is_false_positive(self):
        res = self._check("/admin-secure", "secure")
        self.assertEqual(res.status, "false-positive")

    def test_autonomous_finds_panel_from_robots(self):
        t = Path(self.tmp) / "tgt"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        summary = run_engagement(t, execs, mode="auto", objective="Full scan")
        hyps = json.loads((t / "recon" / "hypotheses.json").read_text())
        ac = [h for h in hyps if h["class"] == "ACCESS-CONTROL"]
        self.assertTrue(any(h["endpoint"] == "/admin-panel" for h in ac))
        findings = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "ACCESS-CONTROL" and f["status"] == "confirmed"
                            and f["endpoint"] == "/admin-panel" for f in findings))


if __name__ == "__main__":
    unittest.main()
