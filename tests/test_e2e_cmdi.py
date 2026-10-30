"""End-to-end tests for the extra lab scenarios, over real local HTTP.

Covers command injection (reflected and blind/time-based), and the two SAFE scenarios
that must NOT be reported as vulnerabilities (echo-only input, access-controlled IDOR).
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.core import run_engagement
from orchestrator.http_exec import HttpCmdiExecutors, HttpIdorExecutors
from tests.fixtures.mock_lab import start_mock_lab

CONFIG = {
    "limits": {"max_iterations": 25, "max_requests": 300, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi"], "focus": ["idor", "cmdi"],
}


class ScenarioTests(unittest.TestCase):
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

    def _finding(self, t):
        return json.loads((t / "findings" / "F-001.json").read_text())

    def test_cmdi_reflected_confirmed(self):
        t = self._target()
        execs = HttpCmdiExecutors(self.base, "/ping", "host", method="GET")
        summary = run_engagement(t, execs, mode="auto", objective="Find CMDI")
        self.assertEqual(summary["findings"].get("confirmed"), 1)
        f = self._finding(t)
        self.assertEqual(f["status"], "confirmed")
        self.assertIn("echo", f["payload"])
        # The marker really came back as command output.
        inj = (t / "findings" / "evidence" / "F-001" / "inject-reflected.response.http").read_text()
        self.assertIn(f["proof"].split()[2], inj)  # the HB... token

    def test_cmdi_blind_timebased_confirmed(self):
        t = self._target()
        execs = HttpCmdiExecutors(self.base, "/ping-blind", "host", method="GET",
                                  blind_delay=1.0)
        run_engagement(t, execs, mode="auto", objective="Find blind CMDI")
        f = self._finding(t)
        self.assertEqual(f["status"], "confirmed")
        self.assertIn("sleep", f["payload"])

    def test_safe_feedback_is_false_positive(self):
        t = self._target()
        execs = HttpCmdiExecutors(self.base, "/feedback", "message", method="POST")
        run_engagement(t, execs, mode="auto", objective="Probe feedback")
        f = self._finding(t)
        self.assertEqual(f["status"], "false-positive")
        self.assertIn("echoed", f["false_positive_reason"])
        # Nothing confirmed -> no report.
        self.assertFalse((t / "reports" / "REPORT.md").exists())

    def test_access_controlled_idor_not_confirmed(self):
        t = self._target()
        execs = HttpIdorExecutors(self.base, "/login", "/me", "/api/safe-user/{id}",
                                  {"username": "wiener", "password": "peter"}, victim_id=2)
        run_engagement(t, execs, mode="auto", objective="Probe safe-user")
        f = self._finding(t)
        self.assertEqual(f["status"], "false-positive")
        self.assertIn("403", f["false_positive_reason"])


if __name__ == "__main__":
    unittest.main()
