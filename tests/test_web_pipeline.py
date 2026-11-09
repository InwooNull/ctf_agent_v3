"""Phase 19: Web pipeline (image, web-service 2-uid boundary, WebClient, scripted
driver, verifier, isolation).

Vault-free: builds its own fixture web instance with a test-only flag (a tiny
stdlib app whose 'bug' serves the service-owned secret over loopback HTTP), never
vault/ or eval/scorer_keys, so the suite runs identically whether or not the
vault is locked. The synthetic dev-set instances themselves are proven by
eval/p19_web_proof.py. Skips the container tests only if docker / the image is
absent.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from solver import web_scripted_driver, verifier  # noqa: E402
from solver.web_harness import WebServiceHarness, WEB_IMAGE  # noqa: E402
from tools import web_service, sandbox  # noqa: E402

IMAGE_READY = sandbox.docker_available() and sandbox.image_available(WEB_IMAGE)

TEST_FLAG = "FLAG{0123456789abcdef}"

# Minimal fixture app: stages the flag into the service-owned DATA_DIR, then exposes it ONLY through
# a 'bug' endpoint (GET /flag) served by the app itself. The agent uid cannot read DATA_DIR directly.
FIXTURE_APP = r'''#!/usr/bin/env python3
import os, http.server
FLAG = os.environ.get("FLAG", "FLAG{unset}")
DATA = os.environ.get("DATA_DIR", "/tmp")
PORT = int(os.environ.get("PORT", "8080"))
with open(os.path.join(DATA, "secret.txt"), "w") as f:
    f.write(FLAG + "\n")

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        if self.path == "/flag":
            body = open(os.path.join(DATA, "secret.txt"), "rb").read()
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
'''

FIXTURE_EXPLOIT = r'''
import re
from web_client import WebClient
with WebClient("http://127.0.0.1:8080", log_dir="/work/web") as c:
    r = c.get("/flag")
    m = re.search(r"FLAG\{[0-9a-f]{16}\}", r.text)
    if m:
        print("CANDIDATE", m.group(0))
    else:
        print("no flag; status", r.status_code)
'''

DIRECT_READ = r'''
import os
hits = []
for p in ["/srv/data", "/srv/data/secret.txt", "/flag.txt"]:
    try:
        (os.listdir(p) if os.path.isdir(p) else open(p, "rb").read()); hits.append(p)
    except OSError:
        pass
print("HITS", hits)
'''

EGRESS = r'''
import socket
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("1.1.1.1", 80)); print("EGRESS_OPEN")
except OSError as e:
    print("EGRESS_BLOCKED", type(e).__name__)
'''


def _make_instance(root, cid="web_fixture"):
    """A world-readable public instance (tree/app.py) the container root can read via /input."""
    d = Path(root) / cid
    (d / "tree").mkdir(parents=True)
    (d / "tree" / "app.py").write_text(FIXTURE_APP)
    (d / "challenge.json").write_text(json.dumps({
        "id": cid, "category": "web", "app_rel": "app.py",
        "files": ["tree/app.py"], "description": "fixture", "flag_format": "FLAG{[0-9a-f]{16}}"}))
    d.chmod(0o755)
    for p in d.rglob("*"):
        p.chmod(0o755 if p.is_dir() else 0o644)
    return d


# ---- host-only tests (no docker) --------------------------------------------

class WebClientHostTest(unittest.TestCase):
    def test_report_candidate_writes_jsonl(self):
        d = Path(tempfile.mkdtemp())
        web_service.report_candidate(d, "FLAG{x}", ["e1"])
        rec = json.loads((d / "candidates.jsonl").read_text())
        self.assertEqual(rec["value"], "FLAG{x}")
        self.assertEqual(rec["evidence_refs"], ["e1"])
        self.assertEqual(rec["status"], "UNVERIFIED")

    def test_transcript_is_byte_safe_and_spills(self):
        # WebClient reuses session.py's helpers; exercise logging without requests (no open()).
        from solver.web_client import WebClient
        d = Path(tempfile.mkdtemp())
        c = WebClient("http://127.0.0.1:8080", log_dir=d)
        self.addCleanup(c.close)
        c._spill_and_log("get", "recv", b"\xff" * 1000, note={"status": 200})
        c._tf.flush()
        recs = [json.loads(l) for l in (d / "web.jsonl").read_text().splitlines()]
        self.assertEqual(recs[-1]["bytes"], 1000)
        self.assertTrue(recs[-1]["preview_truncated"])          # >512 inline preview
        self.assertIn("spill_ref", recs[-1])
        self.assertTrue((d / recs[-1]["spill_ref"]).exists())   # full bytes spilled, not inline

    def test_base_url_normalised(self):
        from solver.web_client import WebClient
        c = WebClient("http://127.0.0.1:8080/", log_dir=tempfile.mkdtemp())
        self.addCleanup(c.close)
        self.assertEqual(c.base_url, "http://127.0.0.1:8080")
        self.assertIsNone(c.cookies)                            # no session before open()


# ---- container tests (web-service boundary) ---------------------------------

@unittest.skipUnless(IMAGE_READY, f"{WEB_IMAGE} not built locally")
class WebBoundaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        cls.chal = _make_instance(t / "arena")
        cls.set = t / "set"
        cls.keys = t / "keys"
        cls.keys.mkdir()
        (cls.keys / "web_fixture.json").write_text(json.dumps({"flag": TEST_FLAG}))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, run_id, code, timeout=60):
        """Stage the boot flag + run `code` on the boundary; return the harness + outcome."""
        boot = self.set / "_boot" / run_id
        boot.mkdir(parents=True, exist_ok=True)
        (boot / "flag").write_text(TEST_FLAG)
        h = WebServiceHarness("harness", self.chal, store_root=self.set / run_id)
        return h, h.run_experiment({"name": "x", "code": code, "timeout": timeout})

    def verdict(self, h):
        return verifier.verify(h.run_dir, "web_fixture", scorer_keys_dir=self.keys)["verdict"]

    def test_client_imports_and_versions_recorded(self):
        code = ("import requests, httpx, bs4\n"
                "print('clients', requests.__version__, httpx.__version__, bs4.__version__)\n"
                "print(open('/opt/ctfagent/versions.txt').read(), end='')\n")
        _, out = self._run("ver", code)
        self.assertEqual(out.execution_status, "ok")
        self.assertIn("clients 2.32.3 0.27.2 4.12.3", out.stdout)
        host = (PROJECT / "docker" / "web_versions.txt").read_text()
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith(("requests=", "httpx=", "beautifulsoup4=")):
                self.assertIn(line, host)

    def test_external_egress_blocked(self):
        h, out = self._run("egress", EGRESS)
        self.assertIn("EGRESS_BLOCKED", out.stdout)
        self.assertEqual(out.sandbox_profile, "container")
        self.assertTrue(out.network_guaranteed)

    def test_solve_over_http_with_evidence(self):
        h, out, flag = web_scripted_driver.solve(
            self.chal, self.set, "pos", FIXTURE_EXPLOIT, "fixture bug", TEST_FLAG)
        self.assertEqual(out.execution_status, "ok")
        self.assertEqual(out.sandbox_profile, "container")
        self.assertEqual(flag, TEST_FLAG)
        exps = [json.loads(l) for l in (h.run_dir / "experiments.jsonl").read_text().splitlines()]
        self.assertEqual(exps[0]["profile_variant"], "web-service")
        self.assertEqual(self.verdict(h), verifier.SOLVED)

    def test_agent_cannot_read_flag_directly(self):
        h, out = self._run("direct", DIRECT_READ)
        self.assertIn("HITS []", out.stdout)                    # service-owned data unreadable
        self.assertEqual(self.verdict(h), verifier.UNVERIFIED)  # no candidate derived

    def test_guess_without_evidence_is_flag_without_solution(self):
        h, out = self._run("fws", "print('benign, no flag')")
        h.report_candidate(TEST_FLAG, [out.exp_id])             # correct value, exp didn't print it
        self.assertEqual(self.verdict(h), verifier.FLAG_WITHOUT_SOLUTION)

    def test_wrong_flag_unverified(self):
        h, out = self._run("wrong", "print('FLAG{' + 'f'*16 + '}')")
        h.report_candidate("FLAG{" + "f" * 16 + "}", [out.exp_id])
        self.assertEqual(self.verdict(h), verifier.UNVERIFIED)


# ---- public-instance hygiene (structural; vault-free) -----------------------

ARENA = PROJECT / "arena" / "web_instances"
PUBLIC_KEYS = {"id", "category", "difficulty", "app_rel", "entry_url", "files",
               "description", "flag_format"}


class WebPublicInstanceTest(unittest.TestCase):
    def test_public_instances_have_no_secret_fields(self):
        dirs = sorted(ARENA.iterdir()) if ARENA.exists() else []
        if not dirs:
            self.skipTest("no web instances generated")
        for d in dirs:
            ch = json.loads((d / "challenge.json").read_text())
            self.assertLessEqual(set(ch), PUBLIC_KEYS)          # no type / answer fields
            self.assertRegex(ch["id"], r"^w19_[0-9a-f]{6}$")
            self.assertEqual(ch["category"], "web")
            self.assertTrue((d / "tree" / ch["app_rel"]).exists())


if __name__ == "__main__":
    unittest.main()
