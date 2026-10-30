"""Triage layer tests: prioritization, graceful degradation, and backend selection.
All offline with a fake invoke — no model, no cost."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator.agents import SimulationExecutors
from orchestrator.core import run_engagement
from orchestrator.triage import TriageLayer, TriagedExecutors, resolve_backend

HYPS = [
    {"id": "H-001", "class": "CMDI", "endpoint": "/ping", "confidence": "medium",
     "reason": "host param", "parameter": "host", "method": "GET"},
    {"id": "H-002", "class": "IDOR", "endpoint": "/api/user/{id}", "confidence": "high",
     "reason": "object id", "parameter": "id", "method": "GET"},
]
SCENARIO = {
    "recon": {"requests_used": 1}, "hypotheses": HYPS,
    "outcomes": {
        "H-001": {"status": "false-positive", "false_positive_reason": "echo", "requests_used": 1},
        "H-002": {"status": "confirmed", "severity": "high", "payload": "swap",
                  "proof": "cross-user", "requests_used": 1,
                  "evidence": {"request-a.http": "q", "response-a.http": "r"}},
    },
}
CONFIG = {"limits": {"max_iterations": 20, "max_requests": 50, "max_runtime_seconds": 900},
          "allowed_skills": ["recon", "idor", "cmdi"], "focus": ["idor", "cmdi"]}


class TriageUnitTests(unittest.TestCase):
    def test_prioritize_reorders_by_llm(self):
        t = TriageLayer(invoke=lambda p: 'order: ["H-002","H-001"]', name="fake")
        out = t.prioritize(HYPS)
        self.assertEqual([h["id"] for h in out], ["H-002", "H-001"])

    def test_prioritize_degrades_on_failure(self):
        def boom(_):
            raise RuntimeError("backend down")
        t = TriageLayer(invoke=boom, name="fake", log=lambda *_: None)
        out = t.prioritize(HYPS)
        self.assertEqual([h["id"] for h in out], ["H-001", "H-002"])  # unchanged

    def test_disabled_when_no_backend(self):
        t = TriageLayer(invoke=None, name="none")
        self.assertFalse(t.available())
        self.assertEqual(t.prioritize(HYPS), HYPS)
        self.assertIsNone(t.explain(HYPS[0]))

    def test_explain_returns_text(self):
        t = TriageLayer(invoke=lambda p: "High impact. Fix: check ownership.", name="fake")
        self.assertIn("Fix", t.explain(HYPS[1]))

    def test_resolve_backend_explicit_and_none(self):
        self.assertEqual(resolve_backend("none"), ("none", None))
        name, inv = resolve_backend("ollama")
        self.assertEqual(name, "ollama")
        self.assertTrue(callable(inv))


class TriageIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.t = Path(self.tmp) / "tgt"
        (self.t / "state").mkdir(parents=True)
        (self.t / "scope.md").write_text("# Scope\n## In scope\n```\nhttps://lab.example.net\n```\n")
        (self.t / "state" / "config.json").write_text(json.dumps(CONFIG))

    def test_loop_honors_triage_priority_and_explains(self):
        # LLM says test H-001 first; and explanations are added to confirmed findings.
        triage = TriageLayer(invoke=lambda p: '["H-001","H-002"]' if "[" in p or "Triage" in p
                             else "Impact: attacker reads other users. Fix: enforce ownership.",
                             name="fake")
        execs = TriagedExecutors(SimulationExecutors(SCENARIO), triage)
        summary = run_engagement(self.t, execs, mode="auto")
        self.assertEqual(summary["status"], "complete")

        hyps = json.loads((self.t / "recon" / "hypotheses.json").read_text())
        self.assertEqual(hyps[0]["id"], "H-001")       # reordered by triage
        self.assertEqual(hyps[0]["priority"], 0)

        confirmed = json.loads((self.t / "findings" / "F-002.json").read_text())
        self.assertIn("explanation", confirmed)
        self.assertIn("ownership", (self.t / "reports" / "REPORT.md").read_text())


if __name__ == "__main__":
    unittest.main()
