"""A tiny stdlib mock of the ACDC/CTFd backend, for offline connector tests.

NOT part of the agent runtime — it lets the connector unit tests exercise the real
CTFdClient (login / list / get / download / attempt) against a loopback server with
no live competition infrastructure. It deliberately reproduces the two behaviours
that bit us live:

  * auth is a **session cookie** from POST /api/v2/auth/login, not a token; every
    other endpoint 401s without it;
  * POST /api/v2/challenges/attempt enforces **same-origin** (Origin/Referer must
    match the host) and 403s otherwise — the bug that cost us a day in the quals.

It can also inject 429s (a finite burst or always) to test rate-limit backoff.

Usage:
    with MockCTFd(flags={14: "acdc2026{...}"}) as srv:
        client = CTFdClient(srv.base_url, name="u", password="p")
        client.login()
        ...
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VALID_USER = {"name": "player", "password": "pw"}


class MockState:
    def __init__(self, flags=None, challenges=None, files=None,
                 rate_limit_burst=0, rate_limit_always=False,
                 user=VALID_USER):
        # challenge_id (int) -> correct flag
        self.flags = {int(k): v for k, v in (flags or {}).items()}
        # list of challenge summary dicts (id, name, category, value, solved_by_me)
        self.challenges = challenges or [
            {"id": cid, "name": f"chal {cid}", "category": "crypto",
             "value": 100, "solved_by_me": False}
            for cid in self.flags
        ]
        # served file path (str) -> raw bytes
        self.files = {k: (v if isinstance(v, bytes) else v.encode()) for k, v in (files or {}).items()}
        self.user = user
        self.rate_limit_remaining = rate_limit_burst
        self.rate_limit_always = rate_limit_always
        self.sessions = set()           # issued session tokens
        self.attempts = []              # (challenge_id, submission) actually scored
        self._tok = 0

    def new_session(self):
        self._tok += 1
        tok = f"sess{self._tok}"
        self.sessions.add(tok)
        return tok

    def should_rate_limit(self):
        if self.rate_limit_always:
            return True
        if self.rate_limit_remaining > 0:
            self.rate_limit_remaining -= 1
            return True
        return False


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    @property
    def st(self):
        return self.server.state

    # -- helpers ----------------------------------------------------------
    def _session_cookie(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("session="):
                return part[len("session="):]
        return None

    def _authed(self):
        return self._session_cookie() in self.st.sessions

    def _send(self, code, obj=None, raw=None, set_cookie=None):
        self.send_response(code)
        if set_cookie:
            self.send_header("Set-Cookie", f"session={set_cookie}; Path=/; HttpOnly")
        if raw is not None:
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(raw)
            return
        body = json.dumps(obj or {}).encode()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except ValueError:
            return {}

    def _same_origin(self):
        host = f"http://{self.headers.get('Host', '')}"
        origin = self.headers.get("Origin")
        referer = self.headers.get("Referer", "")
        return origin == host and referer.startswith(host)

    # -- routing ----------------------------------------------------------
    def do_GET(self):
        path = self.path
        if path == "/api/v2/auth/check/cookie":
            if not self._authed():
                return self._send(401, {"success": False, "message": "no session"})
            return self._send(200, {"success": True, "data": {"authenticated": True},
                                    "user": {"name": self.st.user["name"]}})
        if path == "/api/v2/challenges":
            if not self._authed():
                return self._send(401, {"success": False})
            return self._send(200, {"success": True, "data": self.st.challenges})
        if path.startswith("/api/v2/challenges/"):
            if not self._authed():
                return self._send(401, {"success": False})
            cid = int(path.rsplit("/", 1)[-1])
            summary = next((c for c in self.st.challenges if c["id"] == cid), {})
            files = [f"/files/{cid}/{name}?token=t"
                     for name in self._files_for(cid)]
            data = dict(summary)
            data["description"] = summary.get("description", f"flag is {summary.get('category')}{{...}}")
            data["files"] = files
            return self._send(200, {"success": True, "data": data})
        if path.startswith("/files/"):
            if not self._authed():
                return self._send(401, {"success": False})
            key = path.split("?", 1)[0]
            key = key[len("/files/"):]
            raw = self.st.files.get(key)
            if raw is None:
                return self._send(404, {"success": False})
            return self._send(200, raw=raw)
        return self._send(404, {"success": False})

    def _files_for(self, cid):
        prefix = f"{cid}/"
        return [k[len(prefix):] for k in self.st.files if k.startswith(prefix)]

    def do_POST(self):
        path = self.path
        if path == "/api/v2/auth/login":
            body = self._body()
            if body.get("name") == self.st.user["name"] and body.get("password") == self.st.user["password"]:
                tok = self.st.new_session()
                return self._send(200, {"success": True, "user": {"name": body["name"]}},
                                  set_cookie=tok)
            return self._send(403, {"success": False, "message": "bad credentials"})

        if path == "/api/v2/challenges/attempt":
            if not self._authed():
                return self._send(401, {"success": False})
            if not self._same_origin():
                # the live 403 that cost us a day: same-origin / CSRF check
                return self._send(403, {"success": False,
                                        "message": "request origin or CSRF token incorrect"})
            if self.st.should_rate_limit():
                return self._send(429, {"success": False,
                                        "data": {"status": "ratelimited"},
                                        "message": "too many requests"})
            body = self._body()
            cid = int(body.get("challenge_id"))
            sub = body.get("submission")
            self.st.attempts.append((cid, sub))
            correct = self.st.flags.get(cid)
            status = "correct" if sub == correct else "incorrect"
            msg = "Correct" if status == "correct" else "Incorrect"
            return self._send(200, {"success": True, "data": {"status": status, "message": msg}})

        return self._send(404, {"success": False})


class MockCTFd:
    def __init__(self, **kw):
        self.state = MockState(**kw)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.state = self.state
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = None

    def __enter__(self):
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        return False
