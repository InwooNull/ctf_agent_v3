"""Phase CM8: vol3 memory forensics works OFFLINE on a REAL dump — real structure,
not a `strings` fallback.

Two paths are exercised, both fully offline (--network none, read-only root, non-root,
cap-drop ALL, /work rw) under the governance container profile:

  * Windows (pre-loaded ISF + baked symbol cache): a real 512 MB Windows XP memory image
    (cridex.vmem) is parsed by `windows.pslist`, and we assert the real process tree
    (System / winlogon.exe / services.exe / lsass.exe / explorer.exe ...) comes back
    within the sandbox timeout. This only passes if the image's baked identifier index
    turns the first symbol lookup into a cache HIT; a cold scan of the 801 MB windows
    pack would time out (that was the pre-0.7 failure that forced the strings fallback).

  * Linux (dwarf2json on the fly): challenge-provided kernel symbols (an ELF with DWARF)
    are turned into a vol3 ISF offline by the vendored dwarf2json + `vol-linux-isf`
    helper, proving the generic Linux path that cannot be universally pre-bundled.

The Windows fixture is large and is fetched at test-SETUP time (network allowed there);
the analysis itself is offline. If the fixture is absent the Windows test SKIPS with a
clear needs-style message (user supplies a small dump + matching symbols) — exactly the
tool_gap path the pipeline logs.
"""
import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import contest_files as cf            # noqa: E402
from tools import sandbox                                # noqa: E402

MISC7 = "ctfagent-misc:0.7"
_IMG_READY = sandbox.container_backend_ready(MISC7)

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "mem" / "cridex.vmem"
CRIDEX_SHA256 = "02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d"
# a robust subset of the processes a WinXP cridex image is known to contain
CRIDEX_PROCS = ("System", "winlogon.exe", "services.exe", "lsass.exe", "explorer.exe")


def _sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fixture_ok():
    return FIXTURE.is_file() and _sha256(FIXTURE) == CRIDEX_SHA256


# driver: seed vol's identifier cache from the image-baked full index, then run a real
# Windows plugin against the dump. Runs INSIDE the sandbox (no network).
_WIN_DRIVER = r"""
import os,sys,subprocess,shutil
os.environ.update(HOME='/work',TMPDIR='/work',XDG_CACHE_HOME='/work')
baked=os.environ.get('VOL_BAKED_CACHE','/opt/ctfagent/volcache')
try: shutil.copytree(baked,'/work',dirs_exist_ok=True)
except Exception as e: print('cache-copy-warn',e,file=sys.stderr)
r=subprocess.run(['vol','-q','-f','/input/cridex.vmem','windows.pslist.PsList'],
                 capture_output=True,text=True,timeout=280)
sys.stdout.write(r.stdout)
sys.stderr.write(r.stderr[-800:])
"""


@unittest.skipUnless(_IMG_READY, f"{MISC7} not built")
class TestWindowsRealDumpOffline(unittest.TestCase):
    @unittest.skipUnless(_fixture_ok(),
                         "cridex.vmem fixture missing/!=sha256 — supply a small Windows "
                         "dump at tests/fixtures/mem/cridex.vmem (tool_gap: user-provided)")
    def test_pslist_returns_real_processes_within_timeout(self):
        with tempfile.TemporaryDirectory() as jail:
            name = f"cm8_win_{os.getpid()}"
            t = time.time()
            out, status = cf.run_in_image(
                MISC7, ["python3", "-c", _WIN_DRIVER],
                FIXTURE.parent, jail, name, timeout=360)
            dt = time.time() - t
            self.assertEqual(status, "ok", f"vol run failed: {out[:300]}")
            # real STRUCTURE: known XP processes, not just random strings
            hits = [p for p in CRIDEX_PROCS if p in out]
            self.assertGreaterEqual(len(hits), 3,
                                    f"expected real process names, got hits={hits}\n{out[:500]}")
            # warm-cache proof: a cold 801MB scan would blow past this
            self.assertLess(dt, 340, f"pslist took {dt:.0f}s — baked cache not effective")


@unittest.skipUnless(_IMG_READY, f"{MISC7} not built")
class TestLinuxDwarf2jsonOffline(unittest.TestCase):
    """The generic Linux path: compile an ELF with DWARF (stands in for a challenge's
    vmlinux/debug kernel), build an ISF offline with dwarf2json, assert it is a valid
    vol3 ISF carrying real types+symbols."""
    _D2J_DRIVER = r"""
import json,subprocess,sys,os
os.environ.update(HOME='/work',TMPDIR='/work')
open('/work/t.c','w').write(
 'struct task_demo{int pid;char comm[16];struct task_demo*next;};'
 'struct task_demo init_task_demo={1,"init",0};'
 'const char linux_banner[]="Linux version 5.10.0-demo";'
 'int main(){return init_task_demo.pid;}')
subprocess.run(['gcc','-g','-O0','-o','/work/vmlinux_demo','/work/t.c'],check=True)
r=subprocess.run(['dwarf2json','linux','--elf','/work/vmlinux_demo'],
                 capture_output=True,text=True,timeout=120)
d=json.loads(r.stdout)
print(json.dumps({'keys':sorted(d.keys()),
                  'n_types':len(d.get('user_types',{})),
                  'n_syms':len(d.get('symbols',{})),
                  'has_task':'task_demo' in d.get('user_types',{})}))
"""

    def test_dwarf2json_builds_valid_isf(self):
        with tempfile.TemporaryDirectory() as jail, tempfile.TemporaryDirectory() as empty:
            name = f"cm8_lnx_{os.getpid()}"
            out, status = cf.run_in_image(
                MISC7, ["python3", "-c", self._D2J_DRIVER],
                empty, jail, name, timeout=180)
            self.assertEqual(status, "ok", f"dwarf2json run failed: {out[:300]}")
            res = json.loads(out.strip().splitlines()[-1])
            self.assertEqual(set(res["keys"]) >= {"base_types", "symbols", "user_types"}, True)
            self.assertTrue(res["has_task"])
            self.assertGreater(res["n_syms"], 0)


class TestLinuxNoSymbolsLogsNeed(unittest.TestCase):
    """No kernel symbols shipped with a Linux-looking dump -> the helper emits the NEED
    marker and the host logs a tool_gap/no_kernel_symbols need (strings fallback). This
    is a host-side unit test and needs no container."""

    def test_vol_linux_isf_marker_shape(self):
        # the helper's marker line is the contract the host parses
        helper = PROJECT_ROOT / "docker" / "assets" / "vol-linux-isf.sh"
        txt = helper.read_text()
        self.assertIn('##NEED##', txt)
        self.assertIn('"type":"tool_gap"', txt)
        self.assertIn('"reason":"no_kernel_symbols"', txt)


if __name__ == "__main__":
    unittest.main()
