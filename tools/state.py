#!/usr/bin/env python3
"""state.py — tiny helper to update engagement state without hand-editing JSON.

Stdlib only. The filesystem is the source of truth (see CLAUDE.md §4).

Usage:
  tools/state.py <target_dir> show
  tools/state.py <target_dir> set status running phase recon
  tools/state.py <target_dir> bump iteration
  tools/state.py <target_dir> add-requests 4
  tools/state.py <target_dir> check-limits
  tools/state.py <target_dir> mark-tested <endpoint> <method> <technique>
  tools/state.py <target_dir> is-tested <endpoint> <method> <technique>

<target_dir> is e.g. targets/target-example
"""
import json
import sys
import time
from pathlib import Path


def _load(p: Path, default):
    if p.exists():
        return json.loads(p.read_text())
    return default


def _save(p: Path, data):
    p.write_text(json.dumps(data, indent=2) + "\n")


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2

    target = Path(argv[1])
    cmd = argv[2]
    state_p = target / "state" / "state.json"
    config_p = target / "state" / "config.json"
    tested_p = target / "state" / "tested.json"

    state = _load(state_p, {})
    config = _load(config_p, {})
    tested = _load(tested_p, {"tested": [], "hypotheses_seen": []})
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if cmd == "show":
        print(json.dumps({"state": state, "config": config}, indent=2))
        return 0

    if cmd == "set":
        args = argv[3:]
        for i in range(0, len(args) - 1, 2):
            state[args[i]] = args[i + 1]
        if state.get("started_at") is None and state.get("status") == "running":
            state["started_at"] = now
        state["updated_at"] = now
        _save(state_p, state)
        print("ok")
        return 0

    if cmd == "bump" and len(argv) >= 4 and argv[3] == "iteration":
        state["iteration"] = int(state.get("iteration", 0)) + 1
        state["updated_at"] = now
        _save(state_p, state)
        print(state["iteration"])
        return 0

    if cmd == "add-requests":
        n = int(argv[3])
        state["requests_used"] = int(state.get("requests_used", 0)) + n
        state["updated_at"] = now
        _save(state_p, state)
        print(state["requests_used"])
        return 0

    if cmd == "check-limits":
        limits = config.get("limits", {})
        reasons = []
        if state.get("iteration", 0) >= limits.get("max_iterations", 10**9):
            reasons.append("max_iterations")
        if state.get("requests_used", 0) >= limits.get("max_requests", 10**9):
            reasons.append("max_requests")
        started = state.get("started_at")
        if started and limits.get("max_runtime_seconds"):
            start_s = time.mktime(time.strptime(started, "%Y-%m-%dT%H:%M:%SZ"))
            if (time.time() - start_s) >= limits["max_runtime_seconds"]:
                reasons.append("max_runtime_seconds")
        if reasons:
            print("STOP:" + ",".join(reasons))
            return 1
        print("OK")
        return 0

    if cmd == "mark-tested" and len(argv) >= 6:
        entry = {"endpoint": argv[3], "method": argv[4], "technique": argv[5], "at": now}
        tested["tested"].append(entry)
        _save(tested_p, tested)
        print("marked")
        return 0

    if cmd == "is-tested" and len(argv) >= 6:
        key = (argv[3], argv[4], argv[5])
        for e in tested.get("tested", []):
            if (e.get("endpoint"), e.get("method"), e.get("technique")) == key:
                print("YES")
                return 0
        print("NO")
        return 1

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
