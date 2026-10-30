"""Bounded, in-scope crawler. Discovers the attack surface from a base URL using an
existing (optionally logged-in) Session: links, forms, query params, same-origin JS, and
object identifiers (numeric / UUID). Stays on the allowed hosts and stops at request/depth
limits. No external dependencies — regex-based HTML/JS scraping, good enough for recon.
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import parse_qs, urldefrag, urljoin, urlsplit

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
LINK_RE = re.compile(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', re.I)
FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
ATTR_RE = {k: re.compile(k + r'\s*=\s*["\']([^"\']*)["\']', re.I) for k in ("action", "method")}
INPUT_NAME_RE = re.compile(
    r'<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.I)
JS_EP_RE = re.compile(r'["\'`](/[A-Za-z0-9_\-/.]+)["\'`]')


class CrawlResult:
    def __init__(self):
        self._eps = {}          # (path, method) -> set(params)
        self.object_ids = set()  # ints and uuid strings seen in paths / JSON
        self.js_files = set()
        self.js_endpoints = set()

    def add_endpoint(self, url, method="GET", params=None):
        path = urlsplit(url).path or "/"
        key = (path, method.upper())
        bag = self._eps.setdefault(key, set())
        for p in (params or []):
            bag.add(p)
        for p in parse_qs(urlsplit(url).query):
            bag.add(p)

    def collect_ids_from_path(self, url):
        for seg in urlsplit(url).path.split("/"):
            if seg.isdigit():
                self.object_ids.add(int(seg))
            elif UUID_RE.match(seg):
                self.object_ids.add(seg)

    def collect_ids_from_json(self, obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("id", "userId", "user_id", "account", "accountId") and isinstance(v, int):
                    self.object_ids.add(v)
                self.collect_ids_from_json(v)
        elif isinstance(obj, list):
            for v in obj:
                self.collect_ids_from_json(v)

    def endpoint_list(self):
        return [{"path": p, "method": m, "params": sorted(ps)}
                for (p, m), ps in sorted(self._eps.items())]

    def to_surface(self):
        return {"endpoints": self.endpoint_list(),
                "object_ids": sorted(str(i) for i in self.object_ids),
                "js_files": sorted(self.js_files)}


def crawl_site(base_urls, session, max_requests=60, max_depth=2):
    allowed = {urlsplit(u).netloc for u in base_urls}
    res = CrawlResult()
    seen = set()
    queue = deque((u, 0) for u in base_urls)

    while queue and session.request_count < max_requests:
        url, depth = queue.popleft()
        canon = urldefrag(url)[0]
        if canon in seen:
            continue
        seen.add(canon)

        resp = session.get(url)
        ctype = resp.headers.get("Content-Type", "")
        res.add_endpoint(url, "GET")
        res.collect_ids_from_path(url)
        body = resp.body or ""

        if "json" in ctype:
            res.collect_ids_from_json(resp.json())
            continue

        if "html" in ctype or body.lstrip()[:1] == "<":
            for m in LINK_RE.finditer(body):
                link = urljoin(url, m.group(1))
                if urlsplit(link).netloc not in allowed:
                    continue
                if link.endswith(".js") or "/static/" in urlsplit(link).path:
                    res.js_files.add(link)
                elif urldefrag(link)[0] not in seen and depth < max_depth:
                    queue.append((link, depth + 1))
            for attrs, inner in FORM_RE.findall(body):
                action = ATTR_RE["action"].search(attrs)
                method = ATTR_RE["method"].search(attrs)
                act = urljoin(url, action.group(1)) if action else url
                if urlsplit(act).netloc not in allowed:
                    continue
                res.add_endpoint(act, method.group(1) if method else "GET",
                                 INPUT_NAME_RE.findall(inner))

    for js in list(res.js_files):
        if session.request_count >= max_requests:
            break
        body = session.get(js).body or ""
        for m in JS_EP_RE.finditer(body):
            ep = m.group(1)
            if ep.startswith("/") and not ep.endswith((".js", ".css")):
                res.js_endpoints.add(ep)

    return res
