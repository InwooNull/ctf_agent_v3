"""Phase 7: Reverse pipeline (image, harness, scripted driver, verifier, isolation).

Uses only test-only fixtures (tests/fixtures/), never vault/ or eval/scorer_keys, so
the suite runs identically whether or not the vault is locked for a measurement
batch. The dev-set instances themselves are proven by vault/validate_rev.py.
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
from solver import rev_scripted_driver, verifier  # noqa: E402
from solver.rev_harness import RevHarness, REV_IMAGE  # noqa: E402
from tools import sandbox  # noqa: E402

IMAGE_READY = sandbox.docker_available() and sandbox.image_available(REV_IMAGE)

SMOKE = PROJECT / "eval" / "datasets" / "rev_smoke" / "smoke"


@unittest.skipUnless(IMAGE_READY, f"{REV_IMAGE} not built locally")
class RevImageTest(unittest.TestCase):
    def setUp(self):
        self.store = tempfile.TemporaryDirectory()
        self.addCleanup(self.store.cleanup)

    def run_code(self, code, name="x"):
        h = RevHarness(f"img-{name}", SMOKE, store_root=self.store.name)
        return h, h.run_experiment({"name": name, "code": code, "timeout": 60})

    def test_tools_work_in_container(self):
        code = r'''
import os, subprocess
os.environ["TMPDIR"] = "/work"
open("/work/t.c", "w").write('#include <stdio.h>\nint secret(int x){return x*7+3;}\nint main(){printf("%d\\n",secret(5));return 0;}\n')
def run(*a):
    r = subprocess.run(list(a), capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr
print("gcc", run("gcc", "-O0", "-o", "/work/t", "/work/t.c")[0])
print("exec", run("/work/t")[1].strip())
print("file", "ELF 64-bit" in run("file", "/work/t")[1])
print("objdump", "<secret>:" in run("objdump", "-d", "/work/t")[1])
print("readelf", "ELF Header" in run("readelf", "-h", "/work/t")[1])
print("nm", " T secret" in run("nm", "/work/t")[1])
print("xxd", "7f45 4c46" in run("xxd", "-l", "4", "/work/t")[1])
g = run("gdb", "-batch", "-nx", "-ex", "break secret", "-ex", "run", "-ex", "info registers rdi", "/work/t")[1]
print("gdb", any(l.split()[:1] == ["rdi"] and l.split()[1] == "0x5" for l in g.splitlines()))
'''
        _, out = self.run_code(code, "tools")
        self.assertEqual(out.execution_status, "ok")
        self.assertEqual(out.sandbox_profile, "container")
        for line in ("gcc 0", "exec 38", "file True", "objdump True", "readelf True",
                     "nm True", "xxd True", "gdb True"):
            self.assertIn(line, out.stdout)

    def test_recorded_versions_match_image(self):
        _, out = self.run_code("print(open('/opt/ctfagent/versions.txt').read(), end='')", "ver")
        self.assertEqual(out.stdout, (PROJECT / "docker" / "rev_versions.txt").read_text())

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
        self.assertEqual(sorted(p.name for p in SMOKE.iterdir()), before)   # input dir untouched
        self.assertTrue((h.work_dir / "fs" / "ok.txt").exists())             # landed in the run dir


FIXTURE_SRC = PROJECT / "tests" / "fixtures" / "rev_fixture"
FIXTURE_KEYS = PROJECT / "tests" / "fixtures" / "scorer_keys"
ARENA = PROJECT / "arena" / "rev_instances"
PUBLIC_KEYS = {"id", "category", "difficulty", "files", "description", "flag_format"}

# Solver for the test-only fixture: derives the input from the binary's table, then
# lets the binary confirm it inside the same experiment.
FIXTURE_SOLVER = r"""
import re, subprocess
B = "/input/bin"
def sh(*a, inp=None):
    return subprocess.run(list(a), capture_output=True, input=inp).stdout.decode("latin1")
addr, size = [int(x, 16) for x in next(l.split()[:2] for l in sh("nm", "-S", B).splitlines() if l.endswith(" tfix"))]
for name, a, o, n in re.findall(r"\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", sh("readelf", "-S", "-W", B)):
    a, o, n = int(a, 16), int(o, 16), int(n, 16)
    if a and a <= addr < a + n:
        t = open(B, "rb").read()[o + addr - a:o + addr - a + size]
cand = bytes((v - 3 * i - 1) & 255 for i, v in enumerate(t)).decode()
if "Correct!" in sh(B, inp=(cand + "\n").encode()):
    print("CANDIDATE", cand)
    print("BINARY_ACCEPTS")
"""


@unittest.skipUnless(IMAGE_READY, f"{REV_IMAGE} not built locally")
class RevSolveTest(unittest.TestCase):
    """Positive / negative verdict branches on a test-only fixture compiled in the container.
    Independent of the vault lock; the dev-set instances are proven by vault/validate_rev.py."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        cls.store = t / "runs"
        h = RevHarness("fixture-build", FIXTURE_SRC, store_root=t / "build")
        out = h.run_experiment({"name": "build", "timeout": 120, "code": (
            "import os, subprocess\nos.environ['TMPDIR'] = '/work'\n"
            "print('gcc', subprocess.run(['gcc', '-O0', '-o', '/work/bin', '/input/src.c']).returncode)\n")})
        assert "gcc 0" in out.stdout, out.stdout
        cls.chal = t / "chal"
        cls.chal.mkdir()
        shutil.copyfile(h.work_dir / "build" / "bin", cls.chal / "bin")
        (cls.chal / "bin").chmod(0o755)
        (cls.chal / "challenge.json").write_text(json.dumps({"id": "rev_fixture", "files": ["bin"]}))
        cls.flag = json.loads((FIXTURE_KEYS / "rev_fixture.json").read_text())["flag"]  # grader side only

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def verdict(self, h):
        return verifier.verify(h.run_dir, "rev_fixture", scorer_keys_dir=FIXTURE_KEYS)["verdict"]

    def test_public_instances_have_no_secrets(self):
        dirs = sorted(ARENA.iterdir()) if ARENA.exists() else []
        for d in dirs:
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["bin", "challenge.json"])
            ch = json.loads((d / "challenge.json").read_text())
            self.assertLessEqual(set(ch), PUBLIC_KEYS)          # no type / answer fields
            self.assertRegex(ch["id"], r"^r7_[0-9a-f]{6}$")
        self.assertNotIn(self.flag.encode(), (self.chal / "bin").read_bytes())

    def test_scripted_driver_solves_with_evidence(self):
        h, out, flag = rev_scripted_driver.solve(self.chal, "pos-fixture", FIXTURE_SOLVER, "fixture",
                                                 store_root=self.store)
        self.assertEqual(out.execution_status, "ok")
        self.assertEqual(out.sandbox_profile, "container")
        self.assertTrue(out.network_guaranteed)
        self.assertIn("BINARY_ACCEPTS", out.stdout)
        self.assertEqual(flag, self.flag)
        self.assertEqual(self.verdict(h), verifier.SOLVED)

    def test_binary_rejects_wrong_input(self):
        h = RevHarness("neg-run", self.chal, store_root=self.store)
        code = ("import subprocess\nr=subprocess.run(['/input/bin'],input=b'FLAG{'+b'0'*22+b'}\\n',capture_output=True)\n"
                "print(r.stdout.decode())\n")
        out = h.run_experiment({"name": "wrong", "code": code})
        self.assertIn("Wrong", out.stdout)
        self.assertNotIn("Correct!", out.stdout)

    def test_guess_without_evidence_is_flag_without_solution(self):
        h = RevHarness("neg-guess", self.chal, store_root=self.store)
        out = h.run_experiment({"name": "look", "code": "print(open('/input/challenge.json').read())"})
        h.report_candidate(self.flag, [out.exp_id])   # correct value, but no experiment derived it
        self.assertEqual(self.verdict(h), verifier.FLAG_WITHOUT_SOLUTION)
        h2 = RevHarness("neg-noref", self.chal, store_root=self.store)
        h2.report_candidate(self.flag, [])
        self.assertEqual(self.verdict(h2), verifier.FLAG_WITHOUT_SOLUTION)

    def test_wrong_flag_unverified(self):
        h = RevHarness("neg-wrong", self.chal, store_root=self.store)
        out = h.run_experiment({"name": "p", "code": "print('FLAG{' + '1'*22 + '}')"})
        h.report_candidate("FLAG{" + "1" * 22 + "}", [out.exp_id])
        self.assertEqual(self.verdict(h), verifier.UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
