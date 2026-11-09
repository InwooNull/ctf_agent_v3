"""Phase 21: ctfagent-web:0.2 launch detection (single-service PHP via `php -S` and py3 Flask) on the
web-service 2-uid boundary, plus the private (black-box) source mode and the service-owned flag-file
staging.

Vault-free: every instance is a self-built fixture with a test-only flag, so the suite runs identically
whether or not the vault is locked. The real promoted challenges (guess_harder, poem_collection) are
proven by eval/p21_web_proof.py. Container tests skip if docker / the 0.2 image is absent.
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from solver import verifier  # noqa: E402
from solver.web_harness import WebServiceHarness  # noqa: E402
from tools import sandbox  # noqa: E402

WEB2_IMAGE = "ctfagent-web:0.2"
IMAGE_READY = sandbox.docker_available() and sandbox.image_available(WEB2_IMAGE)
TEST_FLAG = "FLAG{0123456789abcdef}"
CAND_RE = re.compile(r"^CANDIDATE (\S+\{[^}\s]*\})\s*$", re.M)

# --- php fixture: a poems/ LFI (file_get_contents of a user param) with the flag one dir above ------
PHP_INDEX = "<?php echo '<pre>'.file_get_contents($_GET['poem']).'</pre>'; ?>\n"
PHP_LFI_EXPLOIT = r'''
import re, sys
sys.path.insert(0, "/work/_lib")
from web_client import WebClient
with WebClient("http://127.0.0.1:8080", log_dir="/work/web") as c:
    r = c.get("/?poem=../flag.txt")
    m = re.search(r"[A-Za-z0-9_]+\{[^}\s]*\}", r.text)
    if m:
        print("CANDIDATE", m.group(0))
'''

# --- flask fixture: a route that leaks the env flag (stand-in IDOR/debug bug) -----------------------
FLASK_APP = (
    "import os\n"
    "from flask import Flask\n"
    "app = Flask(__name__)\n"
    "FLAG = os.environ.get('FLAG', 'FLAG{unset}')\n"
    "@app.route('/flag')\n"
    "def f():\n"
    "    return FLAG\n"
    "app.run(host='127.0.0.1', port=int(os.environ['PORT']))\n"
)
FLASK_EXPLOIT = r'''
import re, sys
sys.path.insert(0, "/work/_lib")
from web_client import WebClient
with WebClient("http://127.0.0.1:8080", log_dir="/work/web") as c:
    r = c.get("/flag")
    m = re.search(r"FLAG\{[0-9a-f]{16}\}", r.text)
    if m:
        print("CANDIDATE", m.group(0))
'''

DIRECT_READ = r'''
import os
hits = []
for p in ["/srv/tree", "/srv/tree/flag.txt", "/srv/tree/poems", "/srv/data", "/flag.txt"]:
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


def _fix_modes(d):
    d.chmod(0o755)
    for p in d.rglob("*"):
        p.chmod(0o755 if p.is_dir() else 0o644)


def _php_instance(root):
    d = Path(root) / "php_fixture"
    (d / "tree" / "poems").mkdir(parents=True)
    (d / "tree" / "poems" / "index.php").write_text(PHP_INDEX)
    (d / "tree" / "flag.txt").write_text("FLAGHERE\n")          # replaced with the real flag at boundary
    (d / "challenge.json").write_text(json.dumps({
        "id": "php_fixture", "category": "web", "app_rel": "app.py",
        "launch": "php", "source_mode": "private", "docroot": "poems",
        "flag_file": "flag.txt", "flag_token": "FLAGHERE",
        "files": [], "description": "fixture", "flag_format": "FLAG{[0-9a-f]{16}}"}))
    _fix_modes(d)
    return d


def _flask_instance(root):
    d = Path(root) / "flask_fixture"
    (d / "tree").mkdir(parents=True)
    (d / "tree" / "app.py").write_text(FLASK_APP)
    (d / "challenge.json").write_text(json.dumps({
        "id": "flask_fixture", "category": "web", "app_rel": "app.py",
        "launch": "flask", "source_mode": "private",
        "files": [], "description": "fixture", "flag_format": "FLAG{[0-9a-f]{16}}"}))
    _fix_modes(d)
    return d


@unittest.skipUnless(IMAGE_READY, f"{WEB2_IMAGE} not built locally")
class Web2LaunchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        cls.php = _php_instance(t / "a")
        cls.flask = _flask_instance(t / "b")
        cls.keys = t / "keys"
        cls.keys.mkdir()
        for cid in ("php_fixture", "flask_fixture"):
            (cls.keys / f"{cid}.json").write_text(json.dumps({"flag": TEST_FLAG}))
        cls.set = t / "set"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _solve(self, instance, cid, run_id, code, timeout=60):
        boot = self.set / "_boot" / run_id
        boot.mkdir(parents=True, exist_ok=True)
        (boot / "flag").write_text(TEST_FLAG)
        h = WebServiceHarness("harness", instance, store_root=self.set / run_id, image=WEB2_IMAGE)
        out = h.run_experiment({"name": "x", "code": code, "timeout": timeout})
        m = CAND_RE.search(out.stdout or "")
        if m:
            h.report_candidate(m.group(1), [out.exp_id])
        return h, out, (m.group(1) if m else None)

    def verdict(self, h, cid):
        return verifier.verify(h.run_dir, cid, scorer_keys_dir=self.keys)["verdict"]

    def test_php_launch_solve_over_http(self):
        h, out, flag = self._solve(self.php, "php_fixture", "php", PHP_LFI_EXPLOIT)
        self.assertEqual(out.execution_status, "ok", out.stdout)
        self.assertEqual(out.sandbox_profile, "container")
        exps = [json.loads(l) for l in (h.run_dir / "experiments.jsonl").read_text().splitlines()]
        self.assertEqual(exps[0]["profile_variant"], "web-service")
        self.assertEqual(flag, TEST_FLAG)                       # flag staged at boundary, read via LFI
        self.assertEqual(self.verdict(h, "php_fixture"), verifier.SOLVED)

    def test_flask_launch_solve_over_http(self):
        h, out, flag = self._solve(self.flask, "flask_fixture", "flask", FLASK_EXPLOIT)
        self.assertEqual(out.execution_status, "ok", out.stdout)
        self.assertEqual(flag, TEST_FLAG)
        self.assertEqual(self.verdict(h, "flask_fixture"), verifier.SOLVED)

    def test_private_tree_blocks_direct_read(self):
        h, out, flag = self._solve(self.php, "php_fixture", "direct", DIRECT_READ)
        self.assertIn("HITS []", out.stdout)                    # service-owned tree + flag unreadable
        self.assertIsNone(flag)
        self.assertEqual(self.verdict(h, "php_fixture"), verifier.UNVERIFIED)

    def test_external_egress_blocked(self):
        h, out, _ = self._solve(self.php, "php_fixture", "egress", EGRESS)
        self.assertIn("EGRESS_BLOCKED", out.stdout)
        self.assertTrue(out.network_guaranteed)


if __name__ == "__main__":
    unittest.main()
