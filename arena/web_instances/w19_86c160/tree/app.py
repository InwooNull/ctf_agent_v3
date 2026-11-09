#!/usr/bin/env python3
"""Account portal. Log in, then view your account. (Something is too trusting.)"""
import os, sqlite3, http.server, urllib.parse, secrets, html

FLAG = os.environ.get("FLAG", "FLAG{unset}")
DATA = os.environ.get("DATA_DIR", "/tmp")
PORT = int(os.environ.get("PORT", "8080"))
DB = os.path.join(DATA, "app.db")

# --- stage secret: users table; the admin's note is the flag ---
conn = sqlite3.connect(DB)
conn.executescript(
    "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, note TEXT);")
conn.execute("INSERT INTO users VALUES(1,'guest','guest','Welcome, guest. Nothing to see here.')")
conn.execute("INSERT INTO users VALUES(2,'admin',?,?)", (secrets.token_hex(16), FLAG))
conn.commit(); conn.close()

SESSIONS = {}   # token -> uid


def account_note(uid):
    c = sqlite3.connect(DB)
    row = c.execute("SELECT username, note FROM users WHERE id=?", (uid,)).fetchone()
    c.close()
    return row


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def _session_uid(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                return SESSIONS.get(part[len("session="):])
        return None

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index"):
            self._send(200, "<h1>Account Portal</h1>"
                            "<p>POST /login (username,password), then GET /account?id=&lt;your id&gt;.</p>"
                            "<p>Your guest login is guest/guest (you are user id 1).</p>")
            return
        if u.path == "/account":
            uid = self._session_uid()
            if uid is None:
                self._send(401, "<p>Please log in first (POST /login).</p>")
                return
            # BUG (IDOR): returns whatever id is asked for, with no ownership check.
            try:
                want = int(q.get("id", [str(uid)])[0])
            except ValueError:
                self._send(400, "<p>bad id</p>"); return
            row = account_note(want)
            if not row:
                self._send(404, "<p>no such account</p>"); return
            self._send(200, "<h2>Account: %s</h2><pre>%s</pre>" %
                       (html.escape(row[0]), html.escape(row[1])))
            return
        self._send(404, "<p>not found</p>")

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/login":
            n = int(self.headers.get("Content-Length", 0))
            form = urllib.parse.parse_qs(self.rfile.read(n).decode())
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]
            c = sqlite3.connect(DB)
            row = c.execute("SELECT id FROM users WHERE username=? AND password=?",
                            (user, pw)).fetchone()
            c.close()
            if not row:
                self._send(403, "<p>invalid credentials</p>"); return
            tok = secrets.token_hex(16)
            SESSIONS[tok] = row[0]
            self._send(200, "<p>logged in as user id %d</p>" % row[0],
                       extra=[("Set-Cookie", "session=%s; HttpOnly" % tok)])
            return
        self._send(404, "<p>not found</p>")


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
