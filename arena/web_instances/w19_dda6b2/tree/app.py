#!/usr/bin/env python3
"""Product search. Find products by name. (The query builder is naive.)"""
import os, sqlite3, http.server, urllib.parse, html

FLAG = os.environ.get("FLAG", "FLAG{unset}")
DATA = os.environ.get("DATA_DIR", "/tmp")
PORT = int(os.environ.get("PORT", "8080"))
DB = os.path.join(DATA, "shop.db")

# --- stage secret: a products table (public) + a secrets table (the flag) ---
conn = sqlite3.connect(DB)
conn.executescript(
    "CREATE TABLE products(id INTEGER, name TEXT, price TEXT);"
    "CREATE TABLE secrets(k TEXT, v TEXT);")
conn.executemany("INSERT INTO products VALUES(?,?,?)",
                 [(1, "Widget", "9.99"), (2, "Gadget", "19.99"), (3, "Gizmo", "4.99")])
conn.execute("INSERT INTO secrets VALUES('flag', ?)", (FLAG,))
conn.commit(); conn.close()


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path in ("/", "/index"):
            self._send(200, "<h1>Product Search</h1><p>GET /search?q=&lt;name&gt;</p>")
            return
        if u.path == "/search":
            term = q.get("q", [""])[0]
            # BUG (SQLi): the search term is concatenated straight into the SQL text.
            sql = ("SELECT id, name, price FROM products "
                   "WHERE name LIKE '%" + term + "%'")
            c = sqlite3.connect(DB)
            try:
                rows = c.execute(sql).fetchall()
            except sqlite3.Error as e:
                c.close()
                self._send(500, "<p>query error: %s</p>" % html.escape(str(e))); return
            c.close()
            out = ["<h2>Results</h2><table>"]
            for r in rows:
                out.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" %
                           tuple(html.escape(str(x)) for x in r))
            out.append("</table>")
            self._send(200, "".join(out))
            return
        self._send(404, "<p>not found</p>")


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
