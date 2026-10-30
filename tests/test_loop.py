"""End-to-end tests for the Coordinator loop. Stdlib only:  python -m unittest

These exercise the real loop (orchestrator.core) with the offline
SimulationExecutors, and assert the safety properties: it terminates, enforces
limits, refuses missing scope, enforces evidence, and avoids duplicate work.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.agents import SimulationExecutors
from orchestrator.core import run_engagement

SCOPE_OK = """# Scope
## In scope
```
https://lab-1234.web-security-academy.net
```
"""
SCOPE_PLACEHOLDER = """# Scope
## In scope
```
https://YOUR-LAB-ID.web-security-academy.net
```
"""

BASE_SCENARIO = {
    "recon": {"requests_used": 5},
    "hypotheses": [
        {"id": "H-001", "endpoint": "/api/user/{id}", "method": "GET", "parameter": "id",
         "class": "IDOR", "confidence": "high", "reason": "client id"},
        {"id": "H-002", "endpoint": "/feedback", "method": "POST", "parameter": "email",
         "class": "CMDI", "confidence": "medium", "reason": "mail host"},
    ],
    "outcomes": {
        "H-001": {"status": "confirmed", "severity": "high", "payload": "id swap",
                  "proof": "carlos data to wiener", "requests_used": 4,
                  "evidence": {"request-a.http": "GET /1", "response-a.http": "200 wiener",
                               "request-b.http": "GET /2", "response-b.http": "200 carlos"}},
        "H-002": {"status": "false-positive", "false_positive_reason": "echo only",
                  "requests_used": 3},
    },
}


class Clock:
    """Deterministic, monotonically advancing clock for timeout tests."""
    def __init__(self, start=1_000_000.0, step=1.0):
        self.t = start
        self.step = step

    def __call__(self):
        self.t += self.step
        return self.t


def make_target(tmp, scope_text, config=None):
    t = Path(tmp) / "tgt"
    (t / "state").mkdir(parents=True)
    (t / "scope.md").write_text(scope_text)
    cfg = config or {
        "limits": {"max_iterations": 25, "max_requests": 300, "max_runtime_seconds": 1800},
        "allowed_agents": ["recon", "vuln-hunter", "reporter"],
        "allowed_skills": ["recon", "idor", "cmdi"],
        "focus": ["idor", "cmdi"],
    }
    (t / "state" / "config.json").write_text(json.dumps(cfg))
    return t


class LoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_happy_path_terminates_and_reports(self):
        t = make_target(self.tmp, SCOPE_OK)
        summary = run_engagement(t, SimulationExecutors(BASE_SCENARIO),
                                 mode="auto", clock=Clock())
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["termination_reason"], "objective-complete")
        self.assertEqual(summary["findings"].get("confirmed"), 1)
        self.assertEqual(summary["findings"].get("false-positive"), 1)
        self.assertTrue((t / "reports" / "REPORT.md").exists())
        self.assertIn("IDOR", (t / "reports" / "REPORT.md").read_text())

    def test_scope_missing_stops_without_working(self):
        t = make_target(self.tmp, SCOPE_PLACEHOLDER)
        summary = run_engagement(t, SimulationExecutors(BASE_SCENARIO), clock=Clock())
        self.assertTrue(summary["termination_reason"].startswith("scope-missing"))
        self.assertFalse((t / "recon" / "hypotheses.json").exists())

    def test_max_iterations_enforced(self):
        cfg = {"limits": {"max_iterations": 1, "max_requests": 300,
                          "max_runtime_seconds": 1800},
               "allowed_skills": ["recon", "idor", "cmdi"], "focus": ["idor", "cmdi"]}
        t = make_target(self.tmp, SCOPE_OK, cfg)
        summary = run_engagement(t, SimulationExecutors(BASE_SCENARIO), clock=Clock())
        self.assertEqual(summary["termination_reason"], "max-iterations")

    def test_max_requests_enforced(self):
        cfg = {"limits": {"max_iterations": 25, "max_requests": 1,
                          "max_runtime_seconds": 1800},
               "allowed_skills": ["recon", "idor", "cmdi"], "focus": ["idor", "cmdi"]}
        t = make_target(self.tmp, SCOPE_OK, cfg)
        summary = run_engagement(t, SimulationExecutors(BASE_SCENARIO), clock=Clock())
        self.assertEqual(summary["termination_reason"], "max-requests")

    def test_confirmed_without_evidence_is_downgraded(self):
        scenario = json.loads(json.dumps(BASE_SCENARIO))
        scenario["outcomes"]["H-001"].pop("evidence")  # confirmed but no evidence
        t = make_target(self.tmp, SCOPE_OK)
        summary = run_engagement(t, SimulationExecutors(scenario), clock=Clock())
        # No confirmed finding survives -> no report, terminate no-actions.
        self.assertIsNone(summary["findings"].get("confirmed"))
        f = json.loads((t / "findings" / "F-001.json").read_text())
        self.assertEqual(f["status"], "unconfirmed")
        self.assertIn("missing evidence", f["downgraded_reason"])

    def test_dedupe_on_resume_does_not_retest(self):
        t = make_target(self.tmp, SCOPE_OK)
        run_engagement(t, SimulationExecutors(BASE_SCENARIO), clock=Clock())
        tested_after_first = json.loads((t / "state" / "tested.json").read_text())
        n_first = len(tested_after_first["tested"])
        # Resume: run again on the same target. Hypotheses are already tested.
        run_engagement(t, SimulationExecutors(BASE_SCENARIO), clock=Clock())
        tested_after_second = json.loads((t / "state" / "tested.json").read_text())
        self.assertEqual(len(tested_after_second["tested"]), n_first,
                         "resume must not re-test already-tested hypotheses")

    def test_no_skill_class_is_skipped(self):
        scenario = json.loads(json.dumps(BASE_SCENARIO))
        scenario["hypotheses"] = [
            {"id": "H-009", "endpoint": "/x", "method": "GET", "parameter": "q",
             "class": "XSS", "confidence": "high", "reason": "no skill yet"}
        ]
        scenario["outcomes"] = {}
        t = make_target(self.tmp, SCOPE_OK)
        summary = run_engagement(t, SimulationExecutors(scenario), clock=Clock())
        # No skill for XSS -> nothing to hunt -> no confirmed -> no-actions.
        self.assertEqual(summary["termination_reason"], "no-actions")


if __name__ == "__main__":
    unittest.main()
