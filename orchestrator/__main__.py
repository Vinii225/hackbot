"""CLI for the programmatic orchestrator.

Examples:
  # Offline deterministic run against a scenario (safe; no network):
  python -m orchestrator targets/target-example --sim examples/scenario.json

  # Human-in-the-loop (pauses each phase for approval):
  python -m orchestrator targets/target-example --sim examples/scenario.json --mode coop

Real (LLM + curl) runs are not wired in the MVP: use the Markdown agents via
/hackbot-coop and /hackbot-auto, or implement orchestrator.agents.LLMExecutors.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agents import LLMExecutors, SimulationExecutors
from .core import run_engagement


def _approver(phase, payload, store):
    label = payload.get("id") if isinstance(payload, dict) else (payload or "")
    ans = input(f"[coop] next phase: {phase} {label} -- approve? [y/N/stop] ").strip().lower()
    if ans in ("stop", "s"):
        store.state["operator_stop"] = True
        return False
    return ans in ("y", "yes")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="orchestrator", description="Hackbot Coordinator loop")
    ap.add_argument("target_dir", help="path to a target dir, e.g. targets/target-example")
    ap.add_argument("--mode", choices=["auto", "coop"], default="auto")
    ap.add_argument("--objective", default="Find IDOR and command injection")
    ap.add_argument("--sim", metavar="SCENARIO.json",
                    help="run offline with SimulationExecutors from this scenario file")
    args = ap.parse_args(argv)

    if args.sim:
        scenario = json.loads(Path(args.sim).read_text())
        executors = SimulationExecutors(scenario)
    else:
        print("No --sim scenario given. Real LLM executors are not wired in the MVP.\n"
              "Run the Markdown-driven workflow (/hackbot-coop, /hackbot-auto) or pass "
              "--sim <scenario.json> for an offline run.", file=sys.stderr)
        executors = LLMExecutors()

    approver = _approver if args.mode == "coop" else None
    summary = run_engagement(args.target_dir, executors, mode=args.mode,
                             objective=args.objective, approver=approver)
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("status") in ("complete", "terminated") else 1


if __name__ == "__main__":
    sys.exit(main())
