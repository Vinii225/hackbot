"""CLI for the programmatic orchestrator.

Examples:
  # Offline deterministic run against a scenario (safe; no network, no model):
  python -m orchestrator targets/target-example --executor sim --sim examples/scenario.json

  # Real run: drive the Markdown agents via the Claude CLI (makes requests to the target!):
  python -m orchestrator targets/target-example --executor llm --mode coop

  # Inspect the prompts the llm executor would send, without invoking any model:
  python -m orchestrator targets/target-example --print-prompts
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agents import SimulationExecutors
from .core import StateStore, load_scope, run_engagement


def _approver(phase, payload, store):
    label = payload.get("id") if isinstance(payload, dict) else (payload or "")
    ans = input(f"[coop] next phase: {phase} {label} -- approve? [y/N/stop] ").strip().lower()
    if ans in ("stop", "s"):
        store.state["operator_stop"] = True
        return False
    return ans in ("y", "yes")


def _print_prompts(target_dir):
    from . import prompts
    store = StateStore(target_dir).load()
    ok, reason, urls = load_scope(target_dir)
    urls = urls or ["https://IN-SCOPE-HOST.example"]
    print("# RECON PROMPT\n" + prompts.build_recon_prompt(target_dir, urls, "demo objective"))
    hyps = store.hypotheses() or [{"id": "H-001", "endpoint": "/api/user/{id}",
                                   "method": "GET", "parameter": "id", "class": "IDOR"}]
    print("\n\n# HUNT PROMPT\n" + prompts.build_hunt_prompt(target_dir, hyps[0], urls, "idor"))
    print("\n\n# REPORT PROMPT\n" + prompts.build_report_prompt(target_dir, []))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="orchestrator", description="Hackbot Coordinator loop")
    ap.add_argument("target_dir", help="path to a target dir, e.g. targets/target-example")
    ap.add_argument("--mode", choices=["auto", "coop"], default="auto")
    ap.add_argument("--objective", default="Find IDOR and command injection")
    ap.add_argument("--executor", choices=["sim", "llm"], default="sim")
    ap.add_argument("--sim", metavar="SCENARIO.json",
                    help="scenario file for the sim executor (required when --executor sim)")
    ap.add_argument("--print-prompts", action="store_true",
                    help="print the llm prompts for this target and exit (no model call)")
    args = ap.parse_args(argv)

    if args.print_prompts:
        _print_prompts(args.target_dir)
        return 0

    if args.executor == "sim":
        if not args.sim:
            ap.error("--executor sim requires --sim SCENARIO.json")
        executors = SimulationExecutors(json.loads(Path(args.sim).read_text()))
    else:
        from .llm import LLMExecutors
        executors = LLMExecutors()

    approver = _approver if args.mode == "coop" else None
    summary = run_engagement(args.target_dir, executors, mode=args.mode,
                             objective=args.objective, approver=approver)
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("status") in ("complete", "terminated") else 1


if __name__ == "__main__":
    sys.exit(main())
