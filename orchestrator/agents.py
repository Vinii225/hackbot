"""Executors: the seam between the code loop (core.py) and the actual work.

The loop calls executors.recon(...), executors.hunt(...), executors.report(...).
Each writes the same on-disk artifacts the Markdown agents would, following the
contracts in contracts/.

Implementations:
  - SimulationExecutors (here): deterministic, offline, driven by a scenario dict. Used
    by the test suite and for demos. Touches no network.
  - LLMExecutors (orchestrator/llm.py): real work via an LLM coding agent following the
    AGENT.md files plus curl / tools/http.sh.
"""
from __future__ import annotations

import json
from pathlib import Path


def _save(p: Path, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n")


class SimulationExecutors:
    """Replays a scenario so the full loop can be exercised without a network.

    scenario = {
      "recon": {"requests_used": 10, "tech": {...}, "surface": {...}, "js": {...}},
      "hypotheses": [ {hypothesis objects...} ],
      "outcomes": {
        "H-001": {
          "status": "confirmed", "severity": "high", "payload": "...", "proof": "...",
          "requests_used": 4,
          "evidence": {"request-a.http": "...", "response-a.http": "...",
                        "request-b.http": "...", "response-b.http": "..."}
        },
        "H-002": {"status": "false-positive", "false_positive_reason": "...", "requests_used": 3}
      }
    }
    An outcome with status "confirmed" but no "evidence" lets you test the loop's
    evidence-enforcement downgrade.
    """

    def __init__(self, scenario: dict):
        self.scenario = scenario

    def recon(self, store, urls, objective):
        rec = self.scenario.get("recon", {})
        _save(store.dir / "recon" / "tech.json", rec.get("tech", {}))
        _save(store.dir / "recon" / "surface.json", rec.get("surface", {}))
        _save(store.dir / "recon" / "js.json", rec.get("js", {}))
        _save(store.dir / "recon" / "hypotheses.json", self.scenario.get("hypotheses", []))
        return {"requests_used": rec.get("requests_used", 0)}

    def hunt(self, store, hyp, urls):
        hid = hyp["id"]
        outcome = self.scenario.get("outcomes", {}).get(hid, {"status": "unconfirmed"})
        fid = "F-" + hid.split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        evidence = outcome.get("evidence") or {}
        files = []
        for name, content in evidence.items():
            (ev_dir).mkdir(parents=True, exist_ok=True)
            (ev_dir / name).write_text(content)
            files.append(name)

        finding = {
            "id": fid,
            "hypothesis_id": hid,
            "class": hyp.get("class", hyp.get("hypothesis")),
            "status": outcome.get("status", "unconfirmed"),
            "endpoint": hyp.get("endpoint"),
            "method": hyp.get("method"),
            "parameter": hyp.get("parameter"),
            "severity": outcome.get("severity"),
            "payload": outcome.get("payload"),
            "proof": outcome.get("proof"),
            "evidence": {"dir": f"findings/evidence/{fid}/", "files": files},
            "false_positive_reason": outcome.get("false_positive_reason"),
            "requests_used": outcome.get("requests_used", 0),
        }
        finding_file = store.dir / "findings" / f"{fid}.json"
        _save(finding_file, finding)
        return {"finding_file": str(finding_file), "status": finding["status"],
                "requests_used": outcome.get("requests_used", 0)}

    def report(self, store):
        confirmed = [f for f in store.read_findings() if f.get("status") == "confirmed"]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
        confirmed.sort(key=lambda f: order.get(f.get("severity"), 5))
        lines = [f"# Security Assessment Report - {store.dir.name}", ""]
        lines.append(f"- Mode: {store.state.get('mode')}")
        lines.append(f"- Objective: {store.state.get('objective')}")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"- Confirmed findings: {len(confirmed)}")
        lines.append("")
        lines.append("## Findings")
        if not confirmed:
            lines.append("No confirmed findings.")
        for f in confirmed:
            sev = (f.get("severity") or "info").upper()
            lines += [
                "",
                f"### [{sev}] {f.get('class')} - {f.get('endpoint')}",
                f"- Method/Parameter: {f.get('method')} / {f.get('parameter')}",
                f"- Payload: {f.get('payload')}",
                f"- Proof: {f.get('proof')}",
                f"- Evidence: {f.get('evidence', {}).get('dir')} "
                f"({', '.join(f.get('evidence', {}).get('files', [])) or 'none'})",
            ]
        report_file = store.dir / "reports" / "REPORT.md"
        report_file.parent.mkdir(parents=True, exist_ok=True)
        report_file.write_text("\n".join(lines) + "\n")
        return {"report_file": str(report_file), "confirmed": len(confirmed)}
