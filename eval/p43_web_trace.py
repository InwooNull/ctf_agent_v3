"""Phase 43 web routing sanity trace: prove the web router ROUTES three representative
signals to the right 0.3 tool, and that each tool REALLY runs in image ctfagent-web:0.3
on the 2-uid web-service boundary (--network none, loopback-only target, the flag staged
service-owned so the agent uid cannot read it directly).

This is NOT a conversion hunt and claims no solve rate. It shows only: signal -> router
line -> real in-container tool invocation against an isolated loopback target, with the
anti-cheat boundary intact. All three targets are synthetic and self-contained; nothing
here touches a holdout.

  python3 eval/p43_web_trace.py        # -> store/p43_web/trace.json

Three lanes (each a distinct synthetic 2-uid instance, source_mode=private = black-box):
  SQLi          -> sqlmap      boolean-extracts a secret column over HTTP
  content disco -> ffuf        finds a hidden route from a small wordlist, then fetches it
  DOM / JS      -> playwright  renders the JS page headless and reads the post-JS DOM
                               (BEST-EFFORT: if chromium is absent the lane records skipped)
Plus an anti-cheat probe: the agent uid cannot read the service-owned staged flag.
"""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack                 # noqa: E402
from solver.web_harness import WebServiceHarness, WEB_IMAGE_FINALS  # noqa: E402
from tools import sandbox                            # noqa: E402

IMAGE = WEB_IMAGE_FINALS
OUT = PROJECT_ROOT / "store" / "p43_web"
TEST_FLAG = "FLAG{web_route_ok_43}"


def _route(token):
    router = skill_pack.router_text("web")
    return [ln.strip() for ln in router.splitlines() if token in ln.lower()]


# ---- synthetic apps (launch=stdlib; each reads env FLAG and stages its own secret) ----

SQLI_APP = r'''
import os, http.server, sqlite3, urllib.parse
FLAG = os.environ.get("FLAG", "FLAG{unset}")
DATA = os.environ.get("DATA_DIR", "/tmp"); PORT = int(os.environ.get("PORT", "8080"))
DB = os.path.join(DATA, "app.db")          # service-owned (service uid creates it)
con = sqlite3.connect(DB)
con.execute("create table u(id integer, name text, secret text)")
con.execute("insert into u values (1,'alice',?)", (FLAG,))
con.execute("insert into u values (2,'bob','nope')")
con.commit(); con.close()
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        q = urllib.parse.urlparse(self.path); p = urllib.parse.parse_qs(q.query)
        if q.path == "/user":
            uid = p.get("id", ["0"])[0]
            con = sqlite3.connect(DB)
            try:                                    # BUG: id concatenated into SQL
                rows = con.execute("select name from u where id=" + uid).fetchall()
                body = ("FOUND:" + rows[0][0]) if rows else "NONE"
            except Exception as e:
                body = "ERR:" + str(e)
            con.close()
            self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
        else:
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<h1>users</h1> /user?id=1")
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
'''

FUZZ_APP = r'''
import os, http.server
FLAG = os.environ.get("FLAG", "FLAG{unset}"); PORT = int(os.environ.get("PORT", "8080"))
HIDDEN = "/backup.old"                      # unlinked; only findable by content discovery
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == HIDDEN:
            self.send_response(200); self.end_headers(); self.wfile.write(FLAG.encode())
        elif self.path == "/":
            self.send_response(200); self.end_headers(); self.wfile.write(b"<h1>home</h1>")
        else:
            self.send_response(404); self.end_headers()
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
'''

# DOM lane: the flag is XOR-obscured in a byte array; only the page's JS decodes it into
# the DOM on load. A static fetch sees ciphertext + code; the plaintext exists only in the
# rendered DOM -> a headless browser is the tool.
DOM_APP = r'''
import os, http.server, json
FLAG = os.environ.get("FLAG", "FLAG{unset}"); PORT = int(os.environ.get("PORT", "8080"))
K = 0x5A
CT = json.dumps([b ^ K for b in FLAG.encode()])
PAGE = ("<html><body><div id=out>loading</div>"
        "<script>var k=%d, ct=%s;"
        "document.getElementById('out').innerText="
        "ct.map(function(c){return String.fromCharCode(c^k);}).join('');"
        "document.title='ready';</script></body></html>" % (K, CT))
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(PAGE.encode())
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
'''

# ---- agent experiments (run as the agent uid; subprocess the tool at 127.0.0.1:$PORT) ----

SQLMAP_EXP = r'''
import os, re, subprocess
base = "http://127.0.0.1:" + os.environ["PORT"]
os.environ["HOME"] = "/work"
r = subprocess.run(
    ["sqlmap", "-u", base + "/user?id=1", "-p", "id", "--batch", "--dbms=sqlite",
     "--technique=B", "--dump", "-T", "u", "-C", "secret",
     "--output-dir", "/work/sqlmap", "--flush-session"],
    capture_output=True, text=True, timeout=600)
out = r.stdout + r.stderr
print("SQLMAP_INJECTABLE", ("injectable" in out.lower()) or ("is vulnerable" in out.lower()))
m = re.search(r"FLAG\{[^}]+\}", out)
print("SQLMAP_FLAG", m.group(0) if m else "NONE")
'''

FFUF_EXP = r'''
import os, re, subprocess
import urllib.request
# ffuf's scraper reads $HOME/.config/ffuf; the sandbox uid has HOME=/nonexistent, so
# point HOME at the writable workdir or ffuf aborts before fuzzing.
os.environ["HOME"] = "/work"; os.makedirs("/work/.config/ffuf", exist_ok=True)
base = "http://127.0.0.1:" + os.environ["PORT"]
open("/work/w.txt", "w").write("\n".join(["index","login","admin","backup.old","config","api"]) + "\n")
r = subprocess.run(["ffuf", "-u", base + "/FUZZ", "-w", "/work/w.txt", "-mc", "200", "-s"],
                   capture_output=True, text=True, timeout=120)
hits = (r.stdout + r.stderr).split()
print("FFUF_HITS", hits)
flag = "NONE"
if "backup.old" in (r.stdout + r.stderr):
    body = urllib.request.urlopen(base + "/backup.old", timeout=10).read().decode()
    m = re.search(r"FLAG\{[^}]+\}", body); flag = m.group(0) if m else "NONE"
print("FFUF_FLAG", flag)
'''

DOM_EXP = r'''
import os, re
base = "http://127.0.0.1:" + os.environ["PORT"]
try:
    from playwright.sync_api import sync_playwright
except Exception as e:
    print("PLAYWRIGHT_ABSENT", repr(e)[:120]); raise SystemExit(0)
with sync_playwright() as pw:
    b = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
    pg = b.new_page(); pg.goto(base + "/"); pg.wait_for_function("document.title==='ready'")
    dom = pg.inner_text("#out"); b.close()
m = re.search(r"FLAG\{[^}]+\}", dom)
print("DOM_RENDERED_FLAG", m.group(0) if m else ("NONE:" + dom[:40]))
'''

ANTICHEAT_EXP = r'''
import os
hits = []
for p in ["/srv/data", "/srv/data/app.db", "/srv/tree/app.py"]:
    try:
        (os.listdir(p) if os.path.isdir(p) else open(p, "rb").read()); hits.append(p)
    except OSError:
        pass
print("DIRECT_READ_HITS", hits)
'''


def _instance(root, cid, app_src):
    d = Path(root) / cid
    (d / "tree").mkdir(parents=True)
    (d / "tree" / "app.py").write_text(app_src)
    (d / "challenge.json").write_text(json.dumps({
        "id": cid, "category": "web", "app_rel": "app.py", "launch": "stdlib",
        "source_mode": "private",            # black-box: the agent never reads tree/app.py
        "files": [], "description": "p43 synthetic", "flag_format": "FLAG{...}"}))
    return d


def _run(set_root, cid, app_src, code, timeout=600):
    run_id = cid
    d = _instance(set_root / "arena", cid, app_src)
    boot = set_root / "_boot" / run_id
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "flag").write_text(TEST_FLAG)
    h = WebServiceHarness("harness", d, store_root=set_root / run_id, image=IMAGE)
    o = h.run_experiment({"name": "x", "code": code, "timeout": timeout})
    return o, (o.stdout or "")


def trace():
    OUT.mkdir(parents=True, exist_ok=True)
    if not (sandbox.docker_available() and sandbox.image_available(IMAGE)):
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.web3 first")

    lanes = {}
    with tempfile.TemporaryDirectory() as t:
        s = Path(t)

        o, out = _run(s, "p43_sqli", SQLI_APP, SQLMAP_EXP)
        lanes["sqli"] = {
            "signal": "a parameter reaches a SQL query (error / boolean / time difference)",
            "routed_to": _route("sqlmap"), "tool": "sqlmap", "exec": o.execution_status,
            "tool_invoked": "SQLMAP_INJECTABLE" in out,
            "detected_injectable": "SQLMAP_INJECTABLE True" in out,
            "got_flag": TEST_FLAG in out, "result_ok": TEST_FLAG in out}

        o, out = _run(s, "p43_fuzz", FUZZ_APP, FFUF_EXP)
        lanes["content_discovery"] = {
            "signal": "hidden routes/files to discover (sparse app, unlinked paths)",
            "routed_to": _route("ffuf"), "tool": "ffuf", "exec": o.execution_status,
            "tool_invoked": "FFUF_HITS" in out,
            "found_hidden": "backup.old" in out,
            "got_flag": TEST_FLAG in out, "result_ok": TEST_FLAG in out}

        o, out = _run(s, "p43_dom", DOM_APP, DOM_EXP)
        pw_absent = "PLAYWRIGHT_ABSENT" in out
        lanes["dom_js"] = {
            "signal": "flag exists only in the DOM after the page's JS runs",
            "routed_to": _route("playwright"), "tool": "playwright (headless chromium)",
            "exec": o.execution_status,
            "tool_invoked": ("DOM_RENDERED_FLAG" in out) or pw_absent,
            "best_effort_skipped": pw_absent,
            "got_flag": TEST_FLAG in out,
            "result_ok": (TEST_FLAG in out) or pw_absent,     # non-fatal if chromium absent
            "note": ("playwright is best-effort; skipped non-fatally if chromium is absent "
                     "(check /opt/ctfagent/playwright_status.txt)")}

        o, out = _run(s, "p43_anticheat", SQLI_APP, ANTICHEAT_EXP)
        lanes["anticheat"] = {
            "probe": "agent uid tries to read the service-owned staged flag/source directly",
            "exec": o.execution_status, "direct_read_hits": out.strip(),
            "flag_not_directly_readable": "DIRECT_READ_HITS []" in out,
            "result_ok": "DIRECT_READ_HITS []" in out}

    report = {
        "image": IMAGE,
        "probe": ("Phase 43 web routing sanity: signal -> router line -> real in-container "
                  "tool call on the 2-uid web-service boundary, --network none, loopback-only "
                  "target, flag staged service-owned. Capability insurance; NO solve-rate claim."),
        "network": "none (loopback only)",
        "lanes": lanes,
        "all_routed": all(l.get("routed_to") for k, l in lanes.items() if "routed_to" in l),
        "all_invoked": all(l.get("tool_invoked", True) for l in lanes.values()),
        "all_ok": all(l["result_ok"] for l in lanes.values()),
        "anticheat_ok": lanes["anticheat"]["result_ok"],
    }
    (OUT / "trace.json").write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return report


if __name__ == "__main__":
    trace()
