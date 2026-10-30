"""Intentionally-vulnerable LOCAL test fixture: a tiny app with a classic IDOR.

This exists ONLY to validate the hackbot's dynamic pipeline end-to-end on localhost,
the same role DVWA / WebGoat / PortSwigger labs play. It binds to 127.0.0.1 on an
ephemeral port, holds no real data, and is never deployed anywhere.

The vuln: GET /api/user/<id> returns that account (including its apiKey) based only on
the <id> in the URL, without checking that the logged-in session owns that id.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {
    "wiener": {"id": 1, "password": "peter", "email": "wiener@normal-user.net",
               "apiKey": "APIKEY-WIENER-0001"},
    "carlos": {"id": 2, "password": "montoya", "email": "carlos@victim.net",
               "apiKey": "APIKEY-CARLOS-0002"},
}
BY_ID = {u["id"]: dict(username=name, **u) for name, u in USERS.items()}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep test output quiet

    def _session_user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                return part.strip().split("=", 1)[1]
        return None

    def _send(self, status, obj, set_cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if set_cookie:
            self.send_header("Set-Cookie", f"session={set_cookie}; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            form = {k: v[0] for k, v in __import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(raw).items()}
            u = USERS.get(form.get("username", ""))
            if u and u["password"] == form.get("password"):
                return self._send(200, {"login": "ok", "id": u["id"]}, set_cookie=form["username"])
            return self._send(401, {"error": "invalid credentials"})
        self._send(404, {"error": "not found"})

    def do_GET(self):
        who = self._session_user()
        if self.path == "/me":
            if not who:
                return self._send(401, {"error": "not logged in"})
            return self._send(200, {"username": who, "id": USERS[who]["id"]})
        if self.path.startswith("/api/user/"):
            if not who:
                return self._send(401, {"error": "not logged in"})
            try:
                uid = int(self.path.rsplit("/", 1)[1])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            acct = BY_ID.get(uid)
            if not acct:
                return self._send(404, {"error": "no such user"})
            # VULNERABILITY: no check that `who` owns `uid`.
            return self._send(200, {"id": acct["id"], "username": acct["username"],
                                    "email": acct["email"], "apiKey": acct["apiKey"]})
        self._send(404, {"error": "not found"})


def start_mock_lab():
    """Start the fixture on an ephemeral port. Returns (httpd, thread, base_url)."""
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    return httpd, thread, f"http://127.0.0.1:{port}"


if __name__ == "__main__":
    httpd, _, base = start_mock_lab()
    print(f"mock IDOR lab running at {base} (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
