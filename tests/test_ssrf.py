"""SSRF checker (cloud-metadata probe) + autonomous discovery against the local fixture."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_ssrf
from orchestrator.core import run_engagement
from orchestrator.scanner import DynamicExecutors
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session

CONFIG = {
    "limits": {"max_iterations": 60, "max_requests": 600, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "ssrf"], "focus": ["ssrf"],
}


class SsrfTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, name):
        return check_ssrf(Session(self.base),
                          {"endpoint": endpoint, "parameter": "url", "method": "GET"},
                          Path(self.tmp) / name, CheckContext())

    def test_metadata_leak_confirmed(self):
        res = self._check("/fetch", "vuln")
        self.assertEqual(res.status, "confirmed")
        self.assertIn("security-credentials", res.proof)

    def test_blocked_internal_is_false_positive(self):
        res = self._check("/safe-fetch", "safe")
        self.assertEqual(res.status, "false-positive")
        self.assertIn("blocked", res.false_positive_reason)

    def test_autonomous_discovers_and_confirms_ssrf(self):
        t = Path(self.tmp) / "tgt"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        run_engagement(t, execs, mode="auto", objective="Find SSRF")
        hyps = json.loads((t / "recon" / "hypotheses.json").read_text())
        self.assertIn("SSRF", {h["class"] for h in hyps})
        findings = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "SSRF" and f["status"] == "confirmed"
                            and f["endpoint"] == "/fetch" for f in findings))


if __name__ == "__main__":
    unittest.main()
