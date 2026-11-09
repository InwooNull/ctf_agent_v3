"""Phase 47b: the misc image can now COMPILE + RUN recovered source in the sandbox, with
every isolation flag preserved. Gated on ctfagent-misc:0.4 (docker, no live solver/tokens).
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver.misc_harness import MiscHarness, MISC_IMAGE_FINALS  # noqa: E402
from tools import sandbox  # noqa: E402

_DOCKER = sandbox.docker_available() and sandbox.image_available(MISC_IMAGE_FINALS)

# A stand-in for a "recovered program that computes the flag": compile it with g++ and run
# it; it prints flag{<computed>}. Root FS is read-only, so g++ must use TMPDIR=/work.
RECOVERED_CPP = r'''
#include <cstdio>
int main(){
    long acc = 0;
    for (int i = 1; i <= 1337; i++) acc += i;
    // "compute" a flag from the program's own logic (acc = 894453)
    printf("flag{compiled_and_ran_%ld}\n", acc);
    return 0;
}
'''

EXP = r'''
import os, subprocess
os.environ["TMPDIR"] = "/work"          # read-only root -> g++ scratch must go to /work
src = "/work/recovered.cpp"
open(src, "w").write(open("/input/recovered.cpp").read())
c = subprocess.run(["g++", "-O2", src, "-o", "/work/recovered"], capture_output=True, text=True)
print("COMPILE_RC", c.returncode, c.stderr[:200])
r = subprocess.run(["/work/recovered"], capture_output=True, text=True)
print("PROGRAM_OUT", r.stdout.strip())
'''


@unittest.skipUnless(_DOCKER, f"{MISC_IMAGE_FINALS} not built locally")
class TestGppE2E(unittest.TestCase):
    def _challenge(self, tmp):
        d = Path(tmp) / "mr_gpp"
        d.mkdir(parents=True)
        (d / "challenge.json").write_text(json.dumps(
            {"id": "mr_gpp", "category": "misc", "files": ["recovered.cpp"], "description": "x",
             "flag_format": "flag{...}"}))
        (d / "recovered.cpp").write_text(RECOVERED_CPP)
        return d

    def test_compile_and_run_recovered_program(self):
        with tempfile.TemporaryDirectory() as t:
            chal = self._challenge(t)
            h = MiscHarness("gpp", chal, store_root=Path(t) / "store", image=MISC_IMAGE_FINALS)
            o = h.run_experiment({"name": "build_run", "code": EXP, "timeout": 120})
            self.assertEqual(o.execution_status, "ok", o.stdout)
            self.assertIn("COMPILE_RC 0", o.stdout)                      # g++ compiled
            self.assertIn("flag{compiled_and_ran_894453}", o.stdout)     # the program ran + printed

    def test_isolation_flags_preserved(self):
        with tempfile.TemporaryDirectory() as t:
            chal = self._challenge(t)
            h = MiscHarness("gpp2", chal, store_root=Path(t) / "store", image=MISC_IMAGE_FINALS)
            c = h.sandbox_config["container"]
            self.assertEqual(c["network"], "none")
            self.assertTrue(c["read_only_root"])
            self.assertEqual(c["cap_drop"], ["ALL"])
            self.assertTrue(c["no_new_privileges"])

    def test_no_network_during_compile_run(self):
        """Confirm the compile+run experiment really had no egress (isolation intact)."""
        with tempfile.TemporaryDirectory() as t:
            chal = self._challenge(t)
            h = MiscHarness("gpp3", chal, store_root=Path(t) / "store", image=MISC_IMAGE_FINALS)
            net = r'''
import socket
try:
    socket.create_connection(("8.8.8.8", 53), 1.0); print("EGRESS_OPEN")
except OSError:
    print("EGRESS_BLOCKED")
'''
            o = h.run_experiment({"name": "net", "code": net, "timeout": 30})
            self.assertIn("EGRESS_BLOCKED", o.stdout)


if __name__ == "__main__":
    unittest.main()
