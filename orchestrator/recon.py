"""Turn crawl results into a tech fingerprint and conservative vulnerability hypotheses."""
from __future__ import annotations

import re

from tools.crawler import UUID_RE

CMD_PARAM_HINTS = {"host", "ip", "domain", "cmd", "command", "ping", "dns", "url",
                   "target", "addr", "nslookup", "exec", "run"}
ID_PARAM_HINTS = {"id", "user", "userid", "user_id", "account", "accountid", "uid", "oid"}
FILE_PARAM_HINTS = {"file", "filename", "filepath", "path", "doc", "document", "page",
                    "template", "download", "view", "attachment", "resource", "folder"}
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

    for i, h in enumerate(hyps, 1):
        h["id"] = f"H-{i:03d}"
    return hyps
