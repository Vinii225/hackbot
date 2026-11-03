"""Offline executor set driven by a scenario dict. Replays recon, hunt and report with
no network, for the test suite and demos. See scanner.DynamicExecutors for real runs."""
from __future__ import annotations

import json
from pathlib import Path

from .export import write_exports
from .report import write_report


def _save(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


class SimulationExecutors:
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

        files = []
        for name, content in (outcome.get("evidence") or {}).items():
            ev_dir.mkdir(parents=True, exist_ok=True)
            (ev_dir / name).write_text(content)
            files.append(name)

        finding = {
            "id": fid, "hypothesis_id": hid, "class": hyp.get("class", hyp.get("hypothesis")),
            "status": outcome.get("status", "unconfirmed"), "endpoint": hyp.get("endpoint"),
            "method": hyp.get("method"), "parameter": hyp.get("parameter"),
            "severity": outcome.get("severity"), "payload": outcome.get("payload"),
            "proof": outcome.get("proof"),
            "evidence": {"dir": f"findings/evidence/{fid}/", "files": files},
            "false_positive_reason": outcome.get("false_positive_reason"),
            "requests_used": outcome.get("requests_used", 0),
        }
        _save(store.dir / "findings" / f"{fid}.json", finding)
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": finding["status"], "requests_used": outcome.get("requests_used", 0)}

    def report(self, store):
        result = write_report(store)
        result["exports"] = write_exports(store)
        return result
