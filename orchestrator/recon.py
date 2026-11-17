"""Turn crawl results into a tech fingerprint and conservative vulnerability hypotheses."""
from __future__ import annotations

import re

from tools.crawler import UUID_RE, is_destructive

CMD_PARAM_HINTS = {"host", "ip", "domain", "cmd", "command", "ping", "dns", "url",
                   "target", "addr", "nslookup", "exec", "run"}
ID_PARAM_HINTS = {"id", "user", "userid", "user_id", "account", "accountid", "uid", "oid"}
FILE_PARAM_HINTS = {"file", "filename", "filepath", "path", "doc", "document", "page",
                    "template", "download", "view", "attachment", "resource", "folder"}
XSS_PARAM_HINTS = {"q", "query", "search", "s", "term", "keyword", "name", "message",
                   "comment", "title", "text", "input", "content"}
ADMIN_PATH_HINTS = ("admin", "administrator", "manage", "management", "dashboard",
                    "console", "internal", "staff", "moderator", "superuser")
SQLI_PARAM_HINTS = {"category", "cat", "filter", "sort", "order", "search", "q", "query",
                    "name", "product", "productid", "id", "user", "username", "email"}
SSTI_PARAM_HINTS = {"name", "template", "greeting", "preview", "content", "subject",
                    "title", "message", "body", "text"}
REDIRECT_PARAM_HINTS = {"next", "redirect", "redirect_url", "redirecturl", "return",
                        "returnurl", "return_url", "returnto", "dest", "destination",
                        "continue", "goto", "to", "out", "forward", "callback"}
SSRF_PARAM_HINTS = {"url", "uri", "link", "fetch", "feed", "webhook", "proxy", "image",
                    "img", "imageurl", "src", "load", "open", "domain", "callback", "site"}
XXE_PATH_HINTS = ("import", "upload", "xml", "soap", "parse", "ingest", "document", "feed")
HOST_HEADER_PATH_HINTS = ("reset", "forgot", "password", "verify", "confirm", "invite",
                          "link", "activate", "recover")
CSRF_PATH_HINTS = ("change", "update", "edit", "delete", "remove", "add", "create",
                   "transfer", "settings", "profile", "subscribe")
CLICKJACKING_PATH_HINTS = ("panel", "dashboard", "account", "settings", "profile")
_SEG_DIGITS = re.compile(r"^\d+$")


def fingerprint(headers: dict) -> dict:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return {"server": h.get("server"), "x_powered_by": h.get("x-powered-by"),
            "set_cookie": h.get("set-cookie"), "content_type": h.get("content-type")}


def templatize(path: str):
    """Replace numeric / UUID path segments with {id}. Returns (template, [ids])."""
    ids, out = [], []
    for seg in path.split("/"):
        if _SEG_DIGITS.match(seg):
            ids.append(int(seg))
            out.append("{id}")
        elif UUID_RE.match(seg):
            ids.append(seg)
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out), ids


def make_hypotheses(crawl) -> list:
    hyps, seen = [], set()
    endpoints = crawl.endpoint_list()
    all_ids = sorted(i for i in crawl.object_ids if isinstance(i, int))

    # IDOR: endpoints carrying a client-controlled object id in the path.
    for ep in endpoints:
        tmpl, ids = templatize(ep["path"])
        if ids and "{id}" in tmpl and ("IDOR", tmpl) not in seen:
            seen.add(("IDOR", tmpl))
            hyps.append({"endpoint": tmpl, "method": "GET", "parameter": "id",
                         "class": "IDOR", "confidence": "high",
                         "reason": f"Endpoint exposes a client-controlled object id ({tmpl}).",
                         "object_ids": all_ids, "status": "open"})

    # IDOR via id-like query param (no path id).
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in ID_PARAM_HINTS and ("IDOR", ep["path"], p) not in seen:
                seen.add(("IDOR", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "IDOR", "confidence": "medium",
                             "reason": f"Parameter '{p}' looks like a client-controlled object id.",
                             "object_ids": all_ids, "status": "open"})

    # CMDI: params that plausibly reach an OS command.
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in CMD_PARAM_HINTS and ("CMDI", ep["path"], p) not in seen:
                seen.add(("CMDI", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "CMDI", "confidence": "medium",
                             "reason": f"Parameter '{p}' on {ep['path']} may reach an OS command.",
                             "status": "open"})

    # PATH-TRAVERSAL: params that plausibly reference a file/path.
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in FILE_PARAM_HINTS and ("PATH-TRAVERSAL", ep["path"], p) not in seen:
                seen.add(("PATH-TRAVERSAL", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "PATH-TRAVERSAL", "confidence": "medium",
                             "reason": f"Parameter '{p}' on {ep['path']} may reference a file path.",
                             "status": "open"})

    # XSS: params that plausibly get reflected into a response.
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in XSS_PARAM_HINTS and ("XSS", ep["path"], p) not in seen:
                seen.add(("XSS", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "XSS", "confidence": "medium",
                             "reason": f"Parameter '{p}' on {ep['path']} may be reflected into output.",
                             "status": "open"})

    # SQLI: params that plausibly flow into a SQL query (filters, lookups, ids).
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in SQLI_PARAM_HINTS and ("SQLI", ep["path"], p) not in seen:
                seen.add(("SQLI", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "SQLI", "confidence": "medium",
                             "reason": f"Parameter '{p}' on {ep['path']} may flow into a SQL query.",
                             "status": "open"})

    # SSTI: params that plausibly flow into a server-side template render.
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in SSTI_PARAM_HINTS and ("SSTI", ep["path"], p) not in seen:
                seen.add(("SSTI", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "SSTI", "confidence": "medium",
                             "reason": f"Parameter '{p}' on {ep['path']} may be rendered by a "
                                       "server-side template engine.",
                             "status": "open"})

    # OPEN-REDIRECT: params that plausibly set a redirect destination.
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in REDIRECT_PARAM_HINTS and ("OPEN-REDIRECT", ep["path"], p) not in seen:
                seen.add(("OPEN-REDIRECT", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "OPEN-REDIRECT", "confidence": "medium",
                             "reason": f"Parameter '{p}' on {ep['path']} may control a "
                                       "redirect destination.",
                             "status": "open"})

    # SSRF: params that plausibly make the server fetch a URL.
    for ep in endpoints:
        for p in ep["params"]:
            if p.lower() in SSRF_PARAM_HINTS and ("SSRF", ep["path"], p) not in seen:
                seen.add(("SSRF", ep["path"], p))
                hyps.append({"endpoint": ep["path"], "method": ep["method"], "parameter": p,
                             "class": "SSRF", "confidence": "medium",
                             "reason": f"Parameter '{p}' on {ep['path']} may make the server "
                                       "fetch a URL it controls.",
                             "status": "open"})

    # CORS: API-ish endpoints whose cross-origin policy is worth probing.
    for ep in endpoints:
        path = ep["path"]
        if "api" in path.lower() and ("CORS", path) not in seen:
            seen.add(("CORS", path))
            hyps.append({"endpoint": path, "method": ep["method"], "parameter": None,
                         "class": "CORS", "confidence": "low",
                         "reason": f"{path} looks like an API endpoint; probe its "
                                   "cross-origin resource sharing policy.",
                         "status": "open"})

    # XXE: endpoints that look like they ingest an uploaded document / XML body.
    for ep in endpoints:
        path = ep["path"]
        if any(k in path.lower() for k in XXE_PATH_HINTS) and ("XXE", path) not in seen:
            seen.add(("XXE", path))
            hyps.append({"endpoint": path, "method": ep["method"], "parameter": None,
                         "class": "XXE", "confidence": "low",
                         "reason": f"{path} may parse an uploaded XML document; test for "
                                   "external entity resolution.",
                         "status": "open"})

    # HOST-HEADER: endpoints that build absolute links (reset/verify mails) from the
    # request Host, which an attacker can set.
    for ep in endpoints:
        path = ep["path"]
        if any(k in path.lower() for k in HOST_HEADER_PATH_HINTS) \
                and ("HOST-HEADER", path) not in seen:
            seen.add(("HOST-HEADER", path))
            hyps.append({"endpoint": path, "method": ep["method"], "parameter": None,
                         "class": "HOST-HEADER", "confidence": "low",
                         "reason": f"{path} may embed the request Host in a generated link; "
                                   "test Host header injection.",
                         "status": "open"})

    # CSRF: state-changing POST endpoints whose anti-CSRF protection is worth testing.
    for ep in endpoints:
        path = ep["path"]
        if ep["method"].upper() == "POST" and any(k in path.lower() for k in CSRF_PATH_HINTS) \
                and ("CSRF", path) not in seen:
            seen.add(("CSRF", path))
            hyps.append({"endpoint": path, "method": "POST",
                         "parameter": (ep["params"][0] if ep["params"] else None),
                         "class": "CSRF", "confidence": "low",
                         "reason": f"{path} is a state-changing POST; test whether it "
                                   "accepts requests without an anti-CSRF token.",
                         "status": "open"})

    # CLICKJACKING: sensitive-looking GET pages that should refuse to be framed.
    for ep in endpoints:
        path = ep["path"]
        if ep["method"].upper() == "GET" \
                and any(k in path.lower() for k in CLICKJACKING_PATH_HINTS) \
                and ("CLICKJACKING", path) not in seen:
            seen.add(("CLICKJACKING", path))
            hyps.append({"endpoint": path, "method": "GET", "parameter": None,
                         "class": "CLICKJACKING", "confidence": "low",
                         "reason": f"{path} is a sensitive page; test whether it can be "
                                   "framed (missing X-Frame-Options / CSP frame-ancestors).",
                         "status": "open"})

    # ACCESS-CONTROL: privileged-looking paths (admin-like, or disclosed by robots.txt)
    # that should test anonymous access.
    hidden = getattr(crawl, "hidden_paths", set())
    for ep in endpoints:
        path = ep["path"]
        if (path in hidden or any(k in path.lower() for k in ADMIN_PATH_HINTS)) \
                and not is_destructive(path) and ("ACCESS-CONTROL", path) not in seen:
            seen.add(("ACCESS-CONTROL", path))
            why = "disclosed by robots.txt" if path in hidden else "admin-like path"
            hyps.append({"endpoint": path, "method": ep["method"], "parameter": None,
                         "class": "ACCESS-CONTROL", "confidence": "medium",
                         "reason": f"{path} looks like privileged functionality ({why}); "
                                   "test for access without authentication.",
                         "status": "open"})

    for i, h in enumerate(hyps, 1):
        h["id"] = f"H-{i:03d}"
    return hyps
