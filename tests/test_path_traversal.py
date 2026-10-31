"""Path-traversal checker + autonomous discovery against the local fixture."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_path_traversal
from orchestrator.core import run_engagement
from orchestrator.scanner import DynamicExecutors
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session

CONFIG = {
    "limits": {"max_iterations": 30, "max_requests": 300, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi", "path-traversal"],
    "focus": ["idor", "cmdi", "path-traversal"],
}


class PathTraversalTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, name):
        return check_path_traversal(Session(self.base),
                                    {"endpoint": endpoint, "parameter": "file", "method": "GET"},
                                    Path(self.tmp) / name, CheckContext())

    def test_traversal_confirmed(self):
        ev = Path(self.tmp) / "ev"
        res = check_path_traversal(Session(self.base),
                                   {"endpoint": "/download", "parameter": "file",
                                    "method": "GET"}, ev, CheckContext())
        self.assertEqual(res.status, "confirmed")
        self.assertIn("passwd", res.proof)
        self.assertIn("root:x:0:0:", (ev / "traversal.response.http").read_text())

    def test_safe_download_is_false_positive(self):
        res = self._check("/safe-download", "safe")
        self.assertEqual(res.status, "false-positive")
        self.assertIn("403", res.false_positive_reason)

    def test_autonomous_discovers_and_confirms(self):
        t = Path(self.tmp) / "tgt"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        summary = run_engagement(t, execs, mode="auto", objective="Full scan")
        hyps = json.loads((t / "recon" / "hypotheses.json").read_text())
        self.assertIn("PATH-TRAVERSAL", {h["class"] for h in hyps})
        self.assertEqual(summary["findings"].get("confirmed"), 3)
        findings = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "PATH-TRAVERSAL" and f["status"] == "confirmed"
                            for f in findings))


if __name__ == "__main__":
    unittest.main()
