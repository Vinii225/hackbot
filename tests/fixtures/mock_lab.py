"""Intentionally-vulnerable LOCAL test fixture for validating the hackbot end-to-end.

Binds to 127.0.0.1 on an ephemeral port, holds no real data, is never deployed. Same
role DVWA / WebGoat / PortSwigger labs play.

Scenarios:
  GET  /me                      current session's user (for recon)
  GET  /api/user/<id>           IDOR: returns any account by id, no ownership check  (VULN)
  GET  /api/safe-user/<id>      access-controlled: 403 unless you own <id>           (SAFE)
  GET  /ping?host=              reflected OS command injection, output returned       (VULN)
  GET  /ping-blind?host=        blind command injection: executes, no output         (VULN)
  POST /feedback  message=      echoes input as data, never shells out               (SAFE)
  GET  /robots.txt              discloses /admin-panel via Disallow            (info leak)
  GET  /sitemap.xml             lists /sitemap-only-page, linked nowhere else   (info leak)
  GET  /admin-panel             privileged panel reachable without auth               (VULN)
  GET  /admin-secure            admin endpoint, 401 unless authenticated              (SAFE)

The "shell" is EMULATED (_fake_shell): it never spawns a real process or shell. It honors
command separators / substitutions and a tiny safe builtin set (echo, sleep, nslookup,
whoami, id) so injection is observable deterministically without any real execution.
"""
from __future__ import annotations

import html
import json
import posixpath
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {
    "wiener": {"id": 1, "password": "peter", "email": "wiener@normal-user.net",
               "apiKey": "APIKEY-WIENER-0001"},
    "carlos": {"id": 2, "password": "montoya", "email": "carlos@victim.net",
               "apiKey": "APIKEY-CARLOS-0002"},
}
BY_ID = {u["id"]: dict(username=name, **u) for name, u in USERS.items()}
SLEEP_CAP = 3.0  # keep the fixture responsive even if a huge sleep is injected

# HTML/JS so a crawler can DISCOVER the surface the way it would on a real app.
INDEX_HTML = """<!doctype html><html><body>
<h1>Account</h1>
<a href="/api/user/{id}">My account (API)</a>
<a href="/download?file=welcome.txt">Download welcome</a>
<a href="/search?q=test">Search</a>
<form action="/ping" method="GET"><input name="host"><button>Ping</button></form>
<form action="/feedback" method="POST"><input name="message"><button>Send</button></form>
<script src="/static/app.js"></script>
</body></html>"""

# Emulated virtual filesystem for the path-traversal scenario (no real files touched).
DELETED = set()  # records destructive hits so a test can assert the crawler never fires one
BASE_DIR = "/var/www/files"
VFS = {
    "/var/www/files/welcome.txt": "Welcome to the lab.\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nlabuser:x:1000:1000::/home/labuser:/bin/sh\n",
    "/app/secret.txt": "FLAG{path-traversal}\n",
}
LOGIN_HTML = """<!doctype html><html><body><form action="/login" method="POST">
<input name="username"><input name="password"><button>Login</button></form></body></html>"""
APP_JS = """// account widget
fetch('/me').then(r=>r.json()).then(u=>{ fetch('/api/user/'+u.id); });
function ping(h){ return fetch('/ping?host='+encodeURIComponent(h)); }
"""


def _fake_shell(cmd: str) -> str:
    """Emulate a POSIX-ish shell for a small safe builtin set. Never executes anything."""
    def run_one(c: str) -> str:
        c = c.strip()
        if not c:
            return ""
        parts = c.split()
        prog, args = parts[0], parts[1:]
        if prog == "echo":
            return " ".join(args)
        if prog == "sleep":
            try:
                time.sleep(min(float(args[0]), SLEEP_CAP))
            except (ValueError, IndexError):
                pass
            return ""
        if prog in ("nslookup", "ping", "host", "dig"):
            return "Server: fake-dns\nAddress: 127.0.0.1"   # note: does NOT echo the arg
        if prog == "whoami":
            return "labuser"
        if prog == "id":
            return "uid=1000(labuser) gid=1000(labuser)"
        return ""  # unknown command: nothing on stdout

    def expand(s: str) -> str:
        s = re.sub(r"\$\(([^)]*)\)", lambda m: run_one(m.group(1)), s)
        s = re.sub(r"`([^`]*)`", lambda m: run_one(m.group(1)), s)
        return s

    cmd = expand(cmd)
    out = [run_one(seg) for seg in re.split(r"\s*(?:&&|\|\||[;|&\n])\s*", cmd)]
    return "\n".join(o for o in out if o)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _session_user(self):
        for part in self.headers.get("Cookie", "").split(";"):
            if part.strip().startswith("session="):
                return part.strip().split("=", 1)[1]
        return None

    def _query(self):
        q = urllib.parse.urlparse(self.path).query
        return {k: v[0] for k, v in urllib.parse.parse_qs(q).items()}

    def _send(self, status, obj, set_cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if set_cookie:
            self.send_header("Set-Cookie", f"session={set_cookie}; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, status, text, ctype):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}
        if self.path == "/login":
            u = USERS.get(form.get("username", ""))
            if u and u["password"] == form.get("password"):
                return self._send(200, {"login": "ok", "id": u["id"]},
                                  set_cookie=form["username"])
            return self._send(401, {"error": "invalid credentials"})
        if self.path == "/feedback":
            # SAFE: input is treated as data and echoed back; never shelled out.
            return self._send(200, {"received": form.get("message", "")})
        self._send(404, {"error": "not found"})

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        who = self._session_user()

        if path == "/":
            page = INDEX_HTML.format(id=USERS[who]["id"]) if who else LOGIN_HTML
            return self._send_raw(200, page, "text/html")
        if path == "/static/app.js":
            return self._send_raw(200, APP_JS, "application/javascript")

        if path == "/robots.txt":
            return self._send_raw(200, "User-agent: *\nDisallow: /admin-panel\n",
                                  "text/plain")
        if path == "/sitemap.xml":
            loc = f"http://{self.headers.get('Host', '')}/sitemap-only-page"
            return self._send_raw(200, f'<?xml version="1.0"?><urlset><url><loc>{loc}'
                                       "</loc></url></urlset>", "application/xml")
        if path == "/admin-panel":
            return self._send_raw(200, '<!doctype html><html><body><a href='
                                       '"/admin-panel/delete?username=carlos">Delete</a>'
                                       "</body></html>", "text/html")
        if path == "/sitemap-only-page":
            return self._send_raw(200, "<!doctype html><html><body>hidden</body></html>",
                                  "text/html")
        if path == "/admin-secure":
            if not who:
                return self._send(401, {"error": "login required"})  # SAFE: auth enforced
            return self._send(200, {"panel": "admin"})
        if path == "/admin-panel/delete":
            user = self._query().get("username", "")
            if user:
                DELETED.add(user)  # state change: a scanner must never trigger this in recon
            return self._send(200, {"deleted": user})

        if path == "/me":
            if not who:
                return self._send(401, {"error": "not logged in"})
            return self._send(200, {"username": who, "id": USERS[who]["id"]})

        if path.startswith("/api/user/"):
            if not who:
                return self._send(401, {"error": "not logged in"})
            acct = BY_ID.get(_safe_int(path.rsplit("/", 1)[1]))
            if not acct:
                return self._send(404, {"error": "no such user"})
            # VULN: no check that `who` owns this id.
            return self._send(200, _acct_view(acct))

        if path.startswith("/api/safe-user/"):
            if not who:
                return self._send(401, {"error": "not logged in"})
            uid = _safe_int(path.rsplit("/", 1)[1])
            if uid != USERS[who]["id"]:
                return self._send(403, {"error": "forbidden"})   # SAFE: ownership enforced
            return self._send(200, _acct_view(BY_ID[uid]))

        if path == "/download":
            name = self._query().get("file", "")
            # VULN: input joined to the base dir and resolved without containment check,
            # so `../` escapes BASE_DIR and reaches any file in the virtual filesystem.
            resolved = posixpath.normpath(BASE_DIR + "/" + name)
            if resolved in VFS:
                return self._send_raw(200, VFS[resolved], "text/plain")
            return self._send(404, {"error": "file not found"})

        if path == "/safe-download":
            name = self._query().get("file", "")
            resolved = posixpath.normpath(BASE_DIR + "/" + name)
            if not (resolved == BASE_DIR or resolved.startswith(BASE_DIR + "/")):
                return self._send(403, {"error": "forbidden"})   # SAFE: containment enforced
            if resolved in VFS:
                return self._send_raw(200, VFS[resolved], "text/plain")
            return self._send(404, {"error": "file not found"})

        if path == "/search":
            q = self._query().get("q", "")
            # VULN: user input reflected into HTML without encoding.
            return self._send_raw(200, f"<!doctype html><html><body><p>Results for: {q}"
                                       "</p></body></html>", "text/html")

        if path == "/safe-search":
            q = self._query().get("q", "")
            return self._send_raw(200, f"<!doctype html><html><body><p>Results for: "
                                       f"{html.escape(q)}</p></body></html>", "text/html")

        if path == "/ping":
            host = self._query().get("host", "")
            # VULN: user input concatenated into a command; output reflected.
            return self._send(200, {"output": _fake_shell("nslookup " + host)})

        if path == "/ping-blind":
            host = self._query().get("host", "")
            _fake_shell("nslookup " + host)  # VULN: executes, but output not returned
            return self._send(200, {"status": "checked"})

        self._send(404, {"error": "not found"})


def _safe_int(s):
    try:
        return int(s)
    except ValueError:
        return None


def _acct_view(acct):
    return {"id": acct["id"], "username": acct["username"],
            "email": acct["email"], "apiKey": acct["apiKey"]}


def start_mock_lab():
    """Start the fixture on an ephemeral port. Returns (httpd, thread, base_url)."""
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread, f"http://127.0.0.1:{httpd.server_address[1]}"


if __name__ == "__main__":
    httpd, _, base = start_mock_lab()
    print(f"mock lab running at {base} (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
