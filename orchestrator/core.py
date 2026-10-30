"""Core of the programmatic Coordinator loop.

This is the real, code-driven version of the loop described in COORDINATOR.md.
It owns state, enforces every limit, and decides when to stop. The actual recon /
exploitation work is delegated to an "executors" object (see agents.py), so the loop
itself never touches the network and is fully testable offline.

Loop safety ("cuidado com o loop"): the loop terminates on ANY of
  max_iterations, max_requests, max_runtime_seconds, no-progress, missing scope,
  operator stop, objective-complete, or no-actions.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
PLACEHOLDER = "YOUR-LAB-ID"


def _load(p: Path, default):
    return json.loads(p.read_text()) if p.exists() else default


def _save(p: Path, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n")


def _now(clock):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))


class StateStore:
    """Reads/writes the on-disk engagement state under a target directory."""

    def __init__(self, target_dir: str | Path):
        self.dir = Path(target_dir)
        self.config_p = self.dir / "state" / "config.json"
        self.state_p = self.dir / "state" / "state.json"
        self.tested_p = self.dir / "state" / "tested.json"
        self.config = {}
        self.state = {}
        self.tested = {"tested": [], "hypotheses_seen": []}

    def load(self):
        self.config = _load(self.config_p, {})
        self.state = _load(self.state_p, {})
        self.tested = _load(self.tested_p, {"tested": [], "hypotheses_seen": []})
        return self

    @property
    def limits(self):
        return self.config.get("limits", {})

    def save(self, clock=time.time):
        self.state["updated_at"] = _now(clock)
        _save(self.state_p, self.state)
        _save(self.tested_p, self.tested)

    def start(self, mode, objective, clock=time.time):
        self.state.update(
            mode=mode,
            status="running",
            objective=objective,
            current_phase="recon",
            started_at=_now(clock),
            termination_reason=None,
        )
        self.state.setdefault("iteration", 0)
        self.state.setdefault("requests_used", 0)
        self.save(clock)

    def bump_iteration(self, clock=time.time):
        self.state["iteration"] = int(self.state.get("iteration", 0)) + 1
        self.save(clock)
        return self.state["iteration"]

    def add_requests(self, n, clock=time.time):
        self.state["requests_used"] = int(self.state.get("requests_used", 0)) + int(n)
        self.save(clock)

    def elapsed(self, clock):
        started = self.state.get("started_at")
        if not started:
            return 0.0
        start_s = time.mktime(time.strptime(started, "%Y-%m-%dT%H:%M:%SZ"))
        return time.mktime(time.strptime(_now(clock), "%Y-%m-%dT%H:%M:%SZ")) - start_s

    def check_termination(self, clock):
        """Return a termination reason string, or None to continue."""
        lim = self.limits
        if self.state.get("iteration", 0) >= lim.get("max_iterations", 10**9):
            return "max-iterations"
        if self.state.get("requests_used", 0) >= lim.get("max_requests", 10**9):
            return "max-requests"
        if lim.get("max_runtime_seconds") and self.elapsed(clock) >= lim["max_runtime_seconds"]:
            return "max-runtime"
        if self.state.get("operator_stop"):
            return "operator-stop"
        return None

    def terminate(self, reason, clock=time.time):
        self.state["status"] = "terminated" if reason not in ("objective-complete",) else "complete"
        self.state["termination_reason"] = reason
        self.state["current_phase"] = "done"
        self.save(clock)

    # --- dedupe ledger ---
    def is_tested(self, endpoint, method, technique):
        key = (endpoint, method, technique)
        return any(
            (e.get("endpoint"), e.get("method"), e.get("technique")) == key
            for e in self.tested.get("tested", [])
        )

    def hyp_tested(self, hyp_id):
        if hyp_id in self.tested.get("hypotheses_seen", []):
            return True
        return any(e.get("hypothesis_id") == hyp_id for e in self.tested.get("tested", []))

    def mark_tested(self, endpoint, method, technique, hyp_id, clock=time.time):
        self.tested.setdefault("tested", []).append(
            {"endpoint": endpoint, "method": method, "technique": technique,
             "hypothesis_id": hyp_id, "at": _now(clock)}
        )
        seen = self.tested.setdefault("hypotheses_seen", [])
        if hyp_id not in seen:
            seen.append(hyp_id)
        self.save(clock)

    def summary(self):
        findings = self.read_findings()
        by_status = {}
        for f in findings:
            by_status[f.get("status", "?")] = by_status.get(f.get("status", "?"), 0) + 1
        return {
            "status": self.state.get("status"),
            "termination_reason": self.state.get("termination_reason"),
            "iteration": self.state.get("iteration"),
            "requests_used": self.state.get("requests_used"),
            "findings": by_status,
            "report": str(self.dir / "reports" / "REPORT.md"),
        }

    # --- artifact helpers ---
    def hypotheses(self):
        return _load(self.dir / "recon" / "hypotheses.json", [])

    def recon_done(self):
        return (self.dir / "recon" / "hypotheses.json").exists()

    def report_done(self):
        return (self.dir / "reports" / "REPORT.md").exists()

    def read_findings(self):
        out = []
        fdir = self.dir / "findings"
        if fdir.exists():
            for p in sorted(fdir.glob("F-*.json")):
                try:
                    out.append(json.loads(p.read_text()))
                except json.JSONDecodeError:
                    pass
        return out

    def has_confirmed(self):
        return any(f.get("status") == "confirmed" for f in self.read_findings())


def load_scope(target_dir):
    """Enforce 'stop, don't guess': scope must exist and name a real in-scope host.

    Returns (ok: bool, reason: str, urls: list[str]).
    """
    p = Path(target_dir) / "scope.md"
    if not p.exists():
        return False, "scope.md-missing", []
    text = p.read_text()
    urls = re.findall(r"https?://[^\s`]+", text)
    real = [u for u in urls if PLACEHOLDER not in u]
    if not real:
        return False, "no-in-scope-host (still placeholder)", []
    return True, "ok", real


def _skill_available(store, hyp):
    cls = str(hyp.get("class", hyp.get("hypothesis", ""))).lower()
    if cls not in [s.lower() for s in store.config.get("allowed_skills", [])]:
        return None
    skill_dir = REPO_ROOT / "agents" / "vuln-hunter" / "skills" / cls
    return cls if skill_dir.is_dir() else None


def _prioritize(store, hyps):
    focus = [f.lower() for f in store.config.get("focus", [])]

    def key(h):
        cls = str(h.get("class", h.get("hypothesis", ""))).lower()
        fidx = focus.index(cls) if cls in focus else len(focus)
        return (fidx, CONFIDENCE_RANK.get(str(h.get("confidence", "low")).lower(), 3))

    return sorted(hyps, key=key)


def decide(store):
    """Pick the next phase. Returns (phase, payload)."""
    if not store.recon_done():
        return "recon", None
    for hyp in _prioritize(store, store.hypotheses()):
        if _skill_available(store, hyp) is None:
            continue
        if store.hyp_tested(hyp.get("id")):
            continue
        return "hunt", hyp
    if store.has_confirmed() and not store.report_done():
        return "report", None
    return "done", "objective-complete" if store.has_confirmed() else "no-actions"


def _validate_finding(store, finding_file):
    """A confirmed finding is invalid without evidence files on disk; downgrade it."""
    p = Path(finding_file)
    if not p.exists():
        return
    f = json.loads(p.read_text())
    if f.get("status") != "confirmed":
        return
    ev = f.get("evidence", {}) or {}
    files = ev.get("files", [])
    # Resolve the evidence dir relative to the target dir, tolerating a leading
    # "targets/<target>/" prefix in the stored path.
    raw_dir = ev.get("dir", "")
    cand = store.dir / raw_dir
    if not cand.exists() and raw_dir:
        cand = store.dir / "findings" / Path(raw_dir).name
    missing = [fn for fn in files if not (cand / fn).exists()]
    if not files or missing:
        f["status"] = "unconfirmed"
        f["downgraded_reason"] = f"missing evidence files: {missing or 'none listed'}"
        p.write_text(json.dumps(f, indent=2) + "\n")


def run_engagement(target_dir, executors, mode="auto", objective="",
                   clock=time.time, approver=None):
    """Run the Coordinator loop to termination. Returns store.summary()."""
    store = StateStore(target_dir).load()
    ok, reason, urls = load_scope(target_dir)
    if not ok:
        store.start(mode, objective, clock)
        store.terminate(f"scope-missing:{reason}", clock)
        return store.summary()

    store.start(mode, objective, clock)
    stall = 0
    while True:
        term = store.check_termination(clock)
        if term:
            store.terminate(term, clock)
            break
        store.bump_iteration(clock)
        phase, payload = decide(store)
        store.state["current_phase"] = phase
        store.save(clock)

        if phase == "done":
            store.terminate(payload, clock)
            break

        if mode == "coop" and approver is not None:
            if not approver(phase, payload, store):
                store.terminate("operator-stop", clock)
                break

        progressed = False
        if phase == "recon":
            r = executors.recon(store, urls, objective) or {}
            store.add_requests(r.get("requests_used", 0), clock)
            progressed = store.recon_done()
        elif phase == "hunt":
            hyp = payload
            technique = f"{_skill_available(store, hyp)}-test"
            if store.is_tested(hyp["endpoint"], hyp["method"], technique):
                store.mark_tested(hyp["endpoint"], hyp["method"], technique, hyp["id"], clock)
                progressed = False
            else:
                r = executors.hunt(store, hyp, urls) or {}
                store.add_requests(r.get("requests_used", 0), clock)
                if r.get("finding_file"):
                    _validate_finding(store, r["finding_file"])
                store.mark_tested(hyp["endpoint"], hyp["method"], technique, hyp["id"], clock)
                progressed = True
        elif phase == "report":
            executors.report(store) or {}
            store.terminate("objective-complete", clock)
            break

        if progressed:
            stall = 0
        else:
            stall += 1
            if stall >= 2:
                store.terminate("no-progress", clock)
                break

    return store.summary()
