"""Mass assignment checker + autonomous discovery."""
import json, shutil, tempfile, unittest
from pathlib import Path
from orchestrator.checks import CheckContext, check_mass_assignment
from orchestrator.core import run_engagement
from orchestrator.scanner import DynamicExecutors
from tests.fixtures.mock_lab import start_mock_lab
from tools.httpx import Session

CONFIG = {"limits": {"max_iterations": 60, "max_requests": 600, "max_runtime_seconds": 1800},
          "allowed_skills": ["recon", "mass-assignment"], "focus": ["mass-assignment"]}


class MassAssignmentTests(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.base = start_mock_lab()
        self.addCleanup(self.httpd.server_close); self.addCleanup(self.httpd.shutdown)
        self.tmp = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.tmp)

    def _check(self, endpoint, name):
        return check_mass_assignment(Session(self.base),
                                     {"endpoint": endpoint, "method": "POST", "parameter": None},
                                     Path(self.tmp) / name, CheckContext())

    def test_role_bound_confirmed(self):
        self.assertEqual(self._check("/update-profile", "v").status, "confirmed")

    def test_role_ignored_is_false_positive(self):
        self.assertEqual(self._check("/safe-update-profile", "s").status, "false-positive")

    def test_autonomous(self):
        t = Path(self.tmp) / "tgt"; (t / "state").mkdir(parents=True)
        (t / "scope.md").write_text(f"# Scope\n## In scope\n```\n{self.base}\n```\n")
        (t / "state" / "config.json").write_text(json.dumps(CONFIG))
        run_engagement(t, DynamicExecutors(self.base,
                       accounts=[{"username": "wiener", "password": "peter"}]),
                       mode="auto", objective="Find mass assignment")
        findings = [json.loads(p.read_text()) for p in (t / "findings").glob("F-*.json")]
        self.assertTrue(any(f["class"] == "MASS-ASSIGNMENT" and f["status"] == "confirmed"
                            and f["endpoint"] == "/update-profile" for f in findings))


if __name__ == "__main__":
    unittest.main()
