"""End-to-end: run the whole Coordinator loop against a real (local) HTTP target.

Spins up the intentionally-vulnerable mock IDOR lab on localhost, points the dynamic
HttpIdorExecutors at it, and runs run_engagement to completion. Asserts the loop confirms
the IDOR using real request/response evidence captured to disk, and writes a report.

This is the proof that the dynamic pipeline actually works (not just the loop machinery).
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.core import run_engagement
from orchestrator.http_exec import HttpIdorExecutors
from tests.fixtures.mock_lab import start_mock_lab

CONFIG = {
    "limits": {"max_iterations": 25, "max_requests": 300, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi"], "focus": ["idor"],
}


class E2EIdorTests(unittest.TestCase):
    def setUp(self):
        self.httpd, self.thread, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.t = Path(self.tmp) / "tgt"
        (self.t / "state").mkdir(parents=True)
        (self.t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (self.t / "state" / "config.json").write_text(json.dumps(CONFIG))

    def _executors(self):
        return HttpIdorExecutors(
            base_url=self.base, login_path="/login", me_path="/me",
            user_path="/api/user/{id}",
            user={"username": "wiener", "password": "peter"}, victim_id=2)

    def test_confirms_idor_against_live_target(self):
        summary = run_engagement(self.t, self._executors(), mode="auto",
                                 objective="Find IDOR in the lab")
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["findings"].get("confirmed"), 1)

        finding = json.loads((self.t / "findings" / "F-001.json").read_text())
        self.assertEqual(finding["status"], "confirmed")
        self.assertIn("carlos", finding["proof"])

        # Evidence files really exist and contain the victim's leaked data.
        ev = self.t / "findings" / "evidence" / "F-001"
        cross = (ev / "cross-victim.response.http").read_text()
        self.assertIn("carlos@victim.net", cross)
        self.assertIn("APIKEY-CARLOS-0002", cross)
        # Baseline shows the acting user's own data, proving cross-user access.
        base = (ev / "baseline-own.response.http").read_text()
        self.assertIn("wiener@normal-user.net", base)

        report = (self.t / "reports" / "REPORT.md").read_text()
        self.assertIn("IDOR", report)
        self.assertIn("HIGH", report)

    def test_no_false_positive_when_access_controlled(self):
        # Point victim_id at the acting user's OWN id: not cross-user -> not confirmed.
        execs = HttpIdorExecutors(
            base_url=self.base, login_path="/login", me_path="/me",
            user_path="/api/user/{id}",
            user={"username": "wiener", "password": "peter"}, victim_id=1)
        run_engagement(self.t, execs, mode="auto")
        finding = json.loads((self.t / "findings" / "F-001.json").read_text())
        self.assertNotEqual(finding["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
