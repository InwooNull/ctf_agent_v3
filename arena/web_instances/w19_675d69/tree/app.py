#!/usr/bin/env python3
"""Document viewer. Serves files from the pages/ directory. (It does not sanitise the path.)"""
import os, http.server, urllib.parse, html

FLAG = os.environ.get("FLAG", "FLAG{unset}")
DATA = os.environ.get("DATA_DIR", "/tmp")
PORT = int(os.environ.get("PORT", "8080"))
DOCROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")

# --- stage secret: the flag file lives under the service-owned DATA dir,
#     OUTSIDE the document root. Only the path-traversal bug reaches it. ---
with open(os.path.join(DATA, "flag.txt"), "w") as f:
    f.write(FLAG + "\n")


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index"):
            self._send(200, "<h1>Document Viewer</h1>"
                            "<p>GET /file?name=welcome.txt</p>")
            return
        if u.path == "/file":
            name = q.get("name", [""])[0]
            # BUG (path traversal): user input is joined to DOCROOT with no
            # normalisation, so ../ escapes the document root.
            target = os.path.join(DOCROOT, name)
            try:
                with open(target, "rb") as fh:
                    data = fh.read()
            except (OSError, ValueError):
                self._send(404, "<p>no such file</p>"); return
            self._send(200, data, ctype="application/octet-stream")
            return
        self._send(404, "<p>not found</p>")


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
