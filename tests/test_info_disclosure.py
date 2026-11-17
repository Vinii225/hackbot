"""Verbose-error / information-disclosure checker + autonomous discovery."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.checks import CheckContext, check_info_disclosure
from orchestrator.core import run_engagement
from orchestrator.scanner import DynamicExecutors
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session

CONFIG = {
    "limits": {"max_iterations": 60, "max_requests": 600, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "info-disclosure"], "focus": ["info-disclosure"],
}


class InfoDisclosureTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, name):
        return check_info_disclosure(
            Session(self.base),
            {"endpoint": endpoint, "method": "GET", "parameter": "n"},
            Path(self.tmp) / name, CheckContext())

    def test_stack_trace_confirmed(self):
        self.assertEqual(self._check("/compute", "vuln").status, "confirmed")

    def test_generic_error_is_false_positive(self):
        res = self._check("/safe-compute", "safe")
        self.assertEqual(res.status, "false-positive")

    def test_autonomous_discovers_and_confirms(self):
        t = Path(self.tmp) / "tgt"
        (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        execs = DynamicExecutors(self.base,
                                 accounts=[{"username": "wiener", "password": "peter"}])
        run_engagement(t, execs, mode="auto", objective="Find info disclosure")
        findings = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "INFO-DISCLOSURE" and f["status"] == "confirmed"
                            and f["endpoint"] == "/compute" for f in findings))


if __name__ == "__main__":
    unittest.main()
