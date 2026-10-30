"""Minimal HTTP session client with raw-evidence capture. Stdlib only (urllib).

This is the real plumbing the dynamic executors use: a cookie-backed session (so you can
log in as one user and reuse that session across requests), plus helpers to persist the
exact request and response as evidence files.

Not a replacement for Burp/ZAP — just enough to drive authenticated access-control tests
reproducibly and keep raw evidence on disk.
"""
from __future__ import annotations

import http.cookiejar
import json as _json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class Response:
    def __init__(self, req, status, headers, body, elapsed):
        self.request = req            # dict: method, url, headers, body
        self.status = status
        self.headers = headers        # dict
        self.body = body              # str
        self.elapsed = elapsed        # seconds (float)

    def json(self):
        try:
            return _json.loads(self.body)
        except _json.JSONDecodeError:
            return None

    def raw_request(self) -> str:
        r = self.request
        lines = [f"{r['method']} {r['url']}"]
        for k, v in (r.get("headers") or {}).items():
            lines.append(f"{k}: {v}")
        if r.get("body"):
            lines += ["", r["body"] if isinstance(r["body"], str) else r["body"].decode("utf-8", "replace")]
        return "\n".join(lines) + "\n"

    def raw_response(self) -> str:
        lines = [f"HTTP {self.status}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines += ["", self.body]
        return "\n".join(lines) + "\n"


class Session:
    """A cookie-persisting HTTP session."""

    def __init__(self, base_url: str = "", timeout: float = 15.0):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.request_count = 0

    def _url(self, url: str) -> str:
        return url if url.startswith("http") else self.base + url

    def request(self, method, url, data=None, json_body=None, headers=None) -> Response:
        url = self._url(url)
        headers = dict(headers or {})
        body = None
        if json_body is not None:
            body = _json.dumps(json_body).encode()
            headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        req_record = {"method": method, "url": url, "headers": headers,
                      "body": body.decode("utf-8", "replace") if body else None}
        t0 = time.time()
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            status, rbody, rhdrs = resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            status, rbody, rhdrs = e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
        elapsed = time.time() - t0
        self.request_count += 1
        return Response(req_record, status, rhdrs, rbody, elapsed)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def save_evidence(ev_dir, name: str, resp: Response) -> list[str]:
    """Write <name>.request.http and <name>.response.http under ev_dir. Returns filenames."""
    d = Path(ev_dir)
    d.mkdir(parents=True, exist_ok=True)
    req_name, resp_name = f"{name}.request.http", f"{name}.response.http"
    (d / req_name).write_text(resp.raw_request())
    (d / resp_name).write_text(resp.raw_response())
    return [req_name, resp_name]
