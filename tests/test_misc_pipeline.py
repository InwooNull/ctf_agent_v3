"""Phase 17: Misc/Forensics pipeline (image, harness, scripted driver, verifier,
isolation).

Uses only self-built fixtures (a tiny LSB PNG and an EXIF JPEG created inside the
container with a test-only flag), never vault/ or eval/scorer_keys, so the suite
runs identically whether or not the vault is locked. The synthetic dev-set
instances themselves are proven by eval/p17_misc_proof.py.
Skips only if docker / the image is absent.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from solver import misc_scripted_driver, verifier  # noqa: E402
from solver.misc_harness import MiscHarness, MISC_IMAGE  # noqa: E402
from tools import sandbox  # noqa: E402

IMAGE_READY = sandbox.docker_available() and sandbox.image_available(MISC_IMAGE)

# A throwaway challenge dir just to let the harness init for the image tests.
SMOKE = PROJECT / "eval" / "datasets" / "rev_smoke" / "smoke"

TEST_FLAG = "FLAG{0123456789abcdef}"

# Build an LSB PNG and an EXIF JPEG carrying TEST_FLAG, inside the container.
FIXTURE_BUILD = r'''
import os
os.chdir("/work")
from PIL import Image
import numpy as np, subprocess
FLAG = "%s"
# --- lsb.png: flag in LSB of red channel, 16-bit length prefix ---
payload = len(FLAG.encode()).to_bytes(2, "big") + FLAG.encode()
bits = [(b >> (7 - i)) & 1 for b in payload for i in range(8)]
rng = np.random.default_rng(5)
px = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
flat = px.reshape(-1, 3)
for i, b in enumerate(bits):
    flat[i, 0] = (int(flat[i, 0]) & 0xFE) | b
Image.fromarray(px, "RGB").save("lsb.png")
# --- exif.jpg: flag in Comment tag ---
Image.fromarray(rng.integers(0, 256, size=(100, 100, 3), dtype=np.uint8), "RGB").save("exif.jpg", quality=92)
subprocess.run(["exiftool", "-overwrite_original", "-Comment=" + FLAG, "exif.jpg"], check=True,
               capture_output=True)
print("BUILT")
''' % TEST_FLAG


@unittest.skipUnless(IMAGE_READY, f"{MISC_IMAGE} not built locally")
class MiscImageTest(unittest.TestCase):
    def setUp(self):
        self.store = tempfile.TemporaryDirectory()
        self.addCleanup(self.store.cleanup)

    def run_code(self, code, name="x"):
        h = MiscHarness(f"img-{name}", SMOKE, store_root=self.store.name)
        return h, h.run_experiment({"name": name, "code": code, "timeout": 60})

    def test_tools_work_in_container(self):
        code = r'''
import subprocess
def run(*a):
    r = subprocess.run(list(a), capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stdout + r.stderr)
print("file", run("file", "--version")[0] == 0)
print("exiftool", run("exiftool", "-ver")[0] == 0)
print("steghide", "steghide version" in run("steghide", "--version")[1])
print("foremost", run("foremost", "-V")[0] == 0 or "foremost" in run("foremost", "-V")[1])
print("pdftotext", "pdftotext" in run("pdftotext", "-v")[1])
print("tshark", "TShark" in run("tshark", "--version")[1])
import PIL, numpy, pyzbar.pyzbar  # noqa: F401
print("pylibs", True)
'''
        _, out = self.run_code(code, "tools")
        self.assertEqual(out.execution_status, "ok")
        self.assertEqual(out.sandbox_profile, "container")
        for line in ("file True", "exiftool True", "steghide True", "foremost True",
                     "pdftotext True", "tshark True", "pylibs True"):
            self.assertIn(line, out.stdout)

    def test_recorded_versions_present(self):
        _, out = self.run_code("print(open('/opt/ctfagent/versions.txt').read(), end='')", "ver")
        host = (PROJECT / "docker" / "misc_versions.txt").read_text()
        # every version line recorded in the image must appear in the host record
        for line in out.stdout.splitlines():
            if line.strip():
                self.assertIn(line.strip(), host)

    def test_network_is_off(self):
        code = ("import socket\ns=socket.socket(); s.settimeout(3)\n"
                "try:\n    s.connect(('1.1.1.1', 80)); print('NET_OPEN')\n"
                "except OSError as e:\n    print('NET_BLOCKED', type(e).__name__)\n")
        _, out = self.run_code(code, "net")
        self.assertIn("NET_BLOCKED", out.stdout)
        self.assertTrue(out.network_guaranteed)

    def test_no_writes_outside_workdir(self):
        before = sorted(p.name for p in SMOKE.iterdir())
        code = ("import os\nfor p in ['/input/x', '/x', '/tmp/x', '/opt/ctfagent/x', '/home/x']:\n"
                "    try:\n        open(p, 'w').write('x'); print('WROTE', p)\n"
                "    except OSError:\n        print('DENIED', p)\n"
                "open('/work/ok.txt', 'w').write('ok'); print('WORK_OK')\n")
        h, out = self.run_code(code, "fs")
        self.assertNotIn("WROTE", out.stdout)
        self.assertEqual(out.stdout.count("DENIED"), 5)
        self.assertIn("WORK_OK", out.stdout)
        self.assertEqual(sorted(p.name for p in SMOKE.iterdir()), before)
        self.assertTrue((h.work_dir / "fs" / "ok.txt").exists())


ARENA = PROJECT / "arena" / "misc_instances"
PUBLIC_KEYS = {"id", "category", "difficulty", "files", "description", "flag_format"}

# Reference solvers for the two fixtures (same shape as vault/ref_misc.py, test copy).
LSB_SOLVER = r'''
from PIL import Image
import numpy as np, glob, re
f = [x for x in sorted(glob.glob("/input/*")) if not x.endswith("challenge.json")][0]
bits = (np.array(Image.open(f).convert("RGB")).reshape(-1, 3)[:, 0] & 1).astype(int).tolist()
def take(n, off):
    v = 0
    for b in bits[off:off + n]:
        v = (v << 1) | b
    return v
n = take(16, 0)
flag = take(8 * n, 16).to_bytes(n, "big").decode("latin1")
if re.match(r"^FLAG\{[0-9a-f]{16}\}$", flag):
    print("CANDIDATE", flag)
'''


@unittest.skipUnless(IMAGE_READY, f"{MISC_IMAGE} not built locally")
class MiscSolveTest(unittest.TestCase):
    """Positive / negative verdict branches on self-built fixtures. Vault-free."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        cls.store = t / "runs"
        h = MiscHarness("fixture-build", SMOKE, store_root=t / "build")
        out = h.run_experiment({"name": "build", "code": FIXTURE_BUILD, "timeout": 120,
                                "nondeterministic": True})
        assert "BUILT" in out.stdout, out.stdout
        bdir = h.work_dir / "build"
        cls.chal = t / "chal"
        cls.chal.mkdir()
        shutil.copyfile(bdir / "lsb.png", cls.chal / "lsb.png")
        (cls.chal / "challenge.json").write_text(json.dumps({
            "id": "misc_fixture", "category": "misc", "files": ["lsb.png"],
            "description": "LSB fixture", "flag_format": "FLAG{[0-9a-f]{16}}"}))
        cls.keys = t / "keys"
        cls.keys.mkdir()
        (cls.keys / "misc_fixture.json").write_text(json.dumps({"flag": TEST_FLAG}))
        cls.flag = TEST_FLAG

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def verdict(self, h):
        return verifier.verify(h.run_dir, "misc_fixture", scorer_keys_dir=self.keys)["verdict"]

    def test_public_instances_have_no_secrets(self):
        dirs = sorted(ARENA.iterdir()) if ARENA.exists() else []
        for d in dirs:
            ch = json.loads((d / "challenge.json").read_text())
            self.assertLessEqual(set(ch), PUBLIC_KEYS)          # no type / answer fields
            self.assertRegex(ch["id"], r"^m17_[0-9a-f]{6}$")
            self.assertEqual(ch["category"], "misc")

    def test_scripted_driver_solves_with_evidence(self):
        h, out, flag = misc_scripted_driver.solve(self.chal, "pos-fixture", LSB_SOLVER, "fixture",
                                                  store_root=self.store)
        self.assertEqual(out.execution_status, "ok")
        self.assertEqual(out.sandbox_profile, "container")
        self.assertTrue(out.network_guaranteed)
        self.assertEqual(flag, self.flag)
        self.assertEqual(self.verdict(h), verifier.SOLVED)

    def test_fixture_file_has_no_plaintext_flag(self):
        self.assertNotIn(self.flag.encode(), (self.chal / "lsb.png").read_bytes())

    def test_guess_without_evidence_is_flag_without_solution(self):
        h = MiscHarness("neg-guess", self.chal, store_root=self.store)
        out = h.run_experiment({"name": "look", "code": "print('benign, no flag')",
                                "nondeterministic": True})
        h.report_candidate(self.flag, [out.exp_id])   # correct value, no experiment produced it
        self.assertEqual(self.verdict(h), verifier.FLAG_WITHOUT_SOLUTION)
        h2 = MiscHarness("neg-noref", self.chal, store_root=self.store)
        h2.report_candidate(self.flag, [])
        self.assertEqual(self.verdict(h2), verifier.FLAG_WITHOUT_SOLUTION)

    def test_wrong_flag_unverified(self):
        h = MiscHarness("neg-wrong", self.chal, store_root=self.store)
        out = h.run_experiment({"name": "p", "code": "print('FLAG{' + 'f'*16 + '}')",
                                "nondeterministic": True})
        h.report_candidate("FLAG{" + "f" * 16 + "}", [out.exp_id])
        self.assertEqual(self.verdict(h), verifier.UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
