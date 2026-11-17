"""Host header injection checker (Host reflected into a link) + autonomous discovery."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_host_header
from orchestrator.core import run_engagement
from orchestrator.scanner import DynamicExecutors
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session

CONFIG = {
    "limits": {"max_iterations": 60, "max_requests": 600, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "host-header"], "focus": ["host-header"],
}


class HostHeaderTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, name):
        return check_host_header(
            Session(self.base),
            {"endpoint": endpoint, "method": "GET", "parameter": None},
            Path(self.tmp) / name, CheckContext())

    def test_reflected_host_confirmed(self):
        res = self._check("/reset-link", "vuln")
        self.assertEqual(res.status, "confirmed")
        self.assertIn("Host:", res.payload)

    def test_fixed_host_is_false_positive(self):
        res = self._check("/safe-reset-link", "safe")
        self.assertEqual(res.status, "false-positive")
        self.assertIn("fixed canonical host", res.false_positive_reason)

    def test_autonomous_discovers_and_confirms_host_header(self):
        t = Path(self.tmp) / "tgt"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        run_engagement(t, execs, mode="auto", objective="Find host header injection")
        hyps = json.loads((t / "recon" / "hypotheses.json").read_text())
        self.assertIn("HOST-HEADER", {h["class"] for h in hyps})
        findings = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "HOST-HEADER" and f["status"] == "confirmed"
                            and f["endpoint"] == "/reset-link" for f in findings))


if __name__ == "__main__":
    unittest.main()
