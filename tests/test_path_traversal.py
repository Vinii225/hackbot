"""End-to-end tests for the path-traversal skill, over real local HTTP.

Covers: confirmed traversal on the vulnerable endpoint, a SAFE (containment-enforced)
endpoint that must NOT be reported, and autonomous discovery+confirmation via the crawler.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.core import run_engagement
from orchestrator.http_exec import DynamicExecutors, HttpPathTraversalExecutors
from tests.fixtures.mock_lab import start_mock_lab

CONFIG = {
    "limits": {"max_iterations": 30, "max_requests": 300, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi", "path-traversal"],
    "focus": ["idor", "cmdi", "path-traversal"],
}


class PathTraversalTests(unittest.TestCase):
    def setUp(self):
        self.httpd, self.thread, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _target(self):
        t = Path(self.tmp) / f"tgt{id(object())}"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        return t

    def _finding(self, t, fid="F-001"):
        return json.loads((t / "findings" / f"{fid}.json").read_text())

    def test_traversal_confirmed(self):
        t = self._target()
        execs = HttpPathTraversalExecutors(self.base, "/download", "file")
        summary = run_engagement(t, execs, mode="auto", objective="Find path traversal")
        self.assertEqual(summary["findings"].get("confirmed"), 1)
        f = self._finding(t)
        self.assertEqual(f["status"], "confirmed")
        self.assertIn("passwd", f["proof"])
        leak = (t / "findings" / "evidence" / "F-001" / "traversal.response.http").read_text()
        self.assertIn("root:x:0:0:", leak)

    def test_safe_download_is_false_positive(self):
        t = self._target()
        execs = HttpPathTraversalExecutors(self.base, "/safe-download", "file")
        run_engagement(t, execs, mode="auto")
        f = self._finding(t)
        self.assertEqual(f["status"], "false-positive")
        self.assertIn("403", f["false_positive_reason"])
        self.assertFalse((t / "reports" / "REPORT.md").exists())

    def test_autonomous_discovers_and_confirms_traversal(self):
        t = self._target()
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        summary = run_engagement(t, execs, mode="auto", objective="Full scan")
        hyps = json.loads((t / "recon" / "hypotheses.json").read_text())
        self.assertIn("PATH-TRAVERSAL", {h["class"] for h in hyps})
        # IDOR + CMDI + PATH-TRAVERSAL all confirmed from a base URL + credentials only.
        self.assertEqual(summary["findings"].get("confirmed"), 3)
        pt = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "PATH-TRAVERSAL" and f["status"] == "confirmed"
                            for f in pt))


if __name__ == "__main__":
    unittest.main()
