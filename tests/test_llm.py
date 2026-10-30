"""Tests for the real executor seam (orchestrator.llm) using a fake model.

The fake `invoke` plays the role of the LLM: it reads the prompt, detects the phase, and
writes exactly the artifacts a real agent would. This proves the wiring (prompt building,
sidecar request counts, finding/evidence placement, full loop integration) without
calling any model or network.
"""
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from orchestrator import prompts
from orchestrator.core import run_engagement
from orchestrator.llm import LLMExecutors

SCOPE_OK = "# Scope\n## In scope\n```\nhttps://lab-xyz.web-security-academy.net\n```\n"
CONFIG = {
    "limits": {"max_iterations": 25, "max_requests": 300, "max_runtime_seconds": 1800},
    "allowed_skills": ["recon", "idor", "cmdi"], "focus": ["idor", "cmdi"],
}
HYPS = [
    {"id": "H-001", "endpoint": "/api/user/{id}", "method": "GET", "parameter": "id",
     "class": "IDOR", "confidence": "high", "reason": "client id"},
    {"id": "H-002", "endpoint": "/feedback", "method": "POST", "parameter": "email",
     "class": "CMDI", "confidence": "medium", "reason": "mail host"},
]


def make_target(tmp):
    t = Path(tmp) / "tgt"
    (t / "state").mkdir(parents=True)
    (t / "scope.md").write_text(SCOPE_OK)
    (t / "state" / "config.json").write_text(json.dumps(CONFIG))
    return t


def fake_invoke_factory(target):
    """Return an invoke(prompt, cwd) that fulfils each phase like a real agent would."""
    def invoke(prompt, cwd):
        if "PHASE: RECON" in prompt:
            (target / "recon").mkdir(parents=True, exist_ok=True)
            (target / "recon" / "hypotheses.json").write_text(json.dumps(HYPS))
            (target / "recon" / ".requests").write_text("7")
        elif "PHASE: HUNT" in prompt:
            hid = re.search(r'"id": "(H-\d+)"', prompt).group(1)
            fid = "F-" + hid.split("-", 1)[-1]
            fdir = target / "findings"
            (fdir / "evidence" / fid).mkdir(parents=True, exist_ok=True)
            if hid == "H-001":
                for n in ("request-a.http", "response-a.http", "request-b.http", "response-b.http"):
                    (fdir / "evidence" / fid / n).write_text("raw")
                finding = {"id": fid, "hypothesis_id": hid, "class": "IDOR",
                           "status": "confirmed", "severity": "high",
                           "endpoint": "/api/user/2", "method": "GET", "parameter": "id",
                           "payload": "id swap", "proof": "carlos to wiener",
                           "evidence": {"dir": f"findings/evidence/{fid}/",
                                        "files": ["request-a.http", "response-a.http",
                                                  "request-b.http", "response-b.http"]}}
            else:
                finding = {"id": fid, "hypothesis_id": hid, "class": "CMDI",
                           "status": "false-positive", "endpoint": "/feedback",
                           "method": "POST", "parameter": "email",
                           "false_positive_reason": "echo only",
                           "evidence": {"dir": f"findings/evidence/{fid}/", "files": []}}
            (fdir / f"{fid}.json").write_text(json.dumps(finding))
            (fdir / f".requests_{fid}").write_text("4")
        elif "PHASE: REPORT" in prompt:
            (target / "reports").mkdir(parents=True, exist_ok=True)
            (target / "reports" / "REPORT.md").write_text("# Report\nIDOR confirmed\n")
    return invoke


class PromptBuilderTests(unittest.TestCase):
    def test_recon_prompt_has_scope_and_outputs(self):
        p = prompts.build_recon_prompt("targets/t", ["https://in.scope"], "obj")
        self.assertIn("PHASE: RECON", p)
        self.assertIn("https://in.scope", p)
        self.assertIn("hypotheses.json", p)
        self.assertIn("Do NOT claim any vulnerability is confirmed", p)

    def test_hunt_prompt_has_skill_and_evidence_rule(self):
        p = prompts.build_hunt_prompt("targets/t", HYPS[0], ["https://in.scope"], "idor")
        self.assertIn("PHASE: HUNT", p)
        self.assertIn("skills/idor/idor.md", p)
        self.assertIn("'confirmed' REQUIRES those evidence files", p)
        self.assertIn('"id": "H-001"', p)

    def test_report_prompt_targets_report_file(self):
        p = prompts.build_report_prompt("targets/t", [{"id": "F-001"}])
        self.assertIn("PHASE: REPORT", p)
        self.assertIn("REPORT.md", p)
        self.assertIn("['F-001']", p)


class LLMWiringTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_full_loop_with_fake_model(self):
        t = make_target(self.tmp)
        execs = LLMExecutors(invoke=fake_invoke_factory(t), log=lambda *_: None)
        summary = run_engagement(t, execs, mode="auto")
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["termination_reason"], "objective-complete")
        self.assertEqual(summary["findings"].get("confirmed"), 1)
        self.assertEqual(summary["findings"].get("false-positive"), 1)
        self.assertTrue((t / "reports" / "REPORT.md").exists())
        # request counts flowed from the sidecar files into state
        self.assertGreaterEqual(summary["requests_used"], 7 + 4)

    def test_recon_reads_request_sidecar(self):
        t = make_target(self.tmp)
        from orchestrator.core import StateStore
        store = StateStore(t).load()
        execs = LLMExecutors(invoke=fake_invoke_factory(t), log=lambda *_: None)
        r = execs.recon(store, ["https://lab-xyz.web-security-academy.net"], "obj")
        self.assertEqual(r["requests_used"], 7)


if __name__ == "__main__":
    unittest.main()
