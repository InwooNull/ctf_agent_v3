"""Phase 39 tests: the pwndbg-runnable harness fix (exec /dbg/target + agent HOME) and the
p39 CLI routing. Structural checks are docker-free; the end-to-end pwndbg+anti-cheat proof is
gated on docker + image 0.3.
"""
import importlib
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from tools import pwn_service, sandbox  # noqa: E402

IMAGE = "ctfagent-pwn:0.3"


class TestP39HarnessFixStructural(unittest.TestCase):
    def test_pwn_service_has_exec_dbg_and_home(self):
        src = (PROJECT_ROOT / "tools" / "pwn_service.py").read_text()
        self.assertIn("/dbg:rw,exec", src)                 # exec-able debug tmpfs
        self.assertIn('os.environ["HOME"] = "/dbg"', src)  # agent HOME so pwndbg loads
        self.assertIn('shutil.copyfile(runspec["argv"][-1], "/dbg/target")', src)  # public binary only

    def test_dbg_never_receives_the_flag(self):
        # put_flag targets must not include any /dbg path (anti-cheat: /dbg is public binary only)
        src = (PROJECT_ROOT / "tools" / "pwn_service.py").read_text()
        # the staging loop lists flag paths; none should be under /dbg
        self.assertNotIn('put_flag("/dbg', src)
        self.assertNotIn("/dbg/flag", src)


class TestP39Routing(unittest.TestCase):
    def _reload(self, run_id):
        sys.argv = ["pwn_cli.py", run_id]
        import arena.pwn_cli as m
        importlib.reload(m)
        return m

    def test_c0_route_budget30(self):
        m = self._reload("p39c0-r1-xx")
        self.assertEqual(m.pwn_service_harness.PWN_IMAGE, "ctfagent-pwn:0.1")
        self.assertFalse(m.PWNDBG_EXPOSED)
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p39_pwn", "c0"))
        self.assertEqual(m.PWN_BUDGET["max_experiments"], 30)
        self.assertEqual(m.PWN_BUDGET["wall_s"], 3600)

    def test_c1_route_budget30_tools(self):
        m = self._reload("p39c1-r1-xx")
        self.assertEqual(m.pwn_service_harness.PWN_IMAGE, "ctfagent-pwn:0.3")
        self.assertTrue(m.PWNDBG_EXPOSED)
        self.assertTrue(m.ANGR_EXPOSED)
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p39_pwn", "c1"))
        self.assertEqual(m.PWN_BUDGET["max_experiments"], 30)

    def test_c0_c1_same_budget(self):
        b0 = dict(self._reload("p39c0-r1-xx").PWN_BUDGET)
        b1 = dict(self._reload("p39c1-r1-xx").PWN_BUDGET)
        self.assertEqual(b0, b1)

    def tearDown(self):
        sys.argv = ["pwn_cli.py", ""]
        import arena.pwn_cli as m
        importlib.reload(m)


@unittest.skipUnless(sandbox.docker_available() and sandbox.image_available(IMAGE),
                     f"{IMAGE} / docker not available")
class TestP39PwndbgEndToEnd(unittest.TestCase):
    def test_pwndbg_runs_for_agent_and_flag_stays_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            inp = tmp / "in"; inp.mkdir()
            # compile a tiny heap target INSIDE the image -> input/target (the "public" binary)
            (inp / "t.c").write_text(
                "#include <stdlib.h>\n#include <unistd.h>\n#include <stdio.h>\n"
                "int main(){setbuf(stdout,0);void*a=malloc(0x28);void*b=malloc(0x88);free(b);"
                "(void)a;puts(\"r\");char x[8];read(0,x,8);return 0;}\n")
            import subprocess
            subprocess.run(["docker", "run", "--rm", "--network", "none", "-u", "0:0",
                            "-v", f"{inp}:/w:rw", IMAGE, "bash", "-lc",
                            "gcc -O0 /w/t.c -o /w/target && chmod 0755 /w/target && rm /w/t.c"],
                           check=True, capture_output=True)
            agent = (
                "import subprocess\n"
                "cmds=['-ex','source /opt/pwndbg/gdbinit.py','-ex','set pagination off',"
                "'-ex','break main','-ex','run']+sum([['-ex','next']]*8,[])+"
                "['-ex','heap','-ex','tcachebins','-ex','quit']\n"
                "r=subprocess.run(['gdb','-q','-nx']+cmds+['/dbg/target'],"
                "capture_output=True,text=True,timeout=150)\n"
                "o=r.stdout+r.stderr\n"
                "print('PWNDBG_LOADED', ('loaded' in o and 'pwndbg' in o) or ('Allocated chunk' in o))\n"
                "print('HEAP_OK', ('Allocated chunk' in o) or ('Top chunk' in o))\n"
                "print('POETRY_ERR', ('PermissionError' in o and 'poetry' in o))\n"
                "hits=[]\n"
                "for p in ('/srv/flag.txt','/srv/flag','/flag.txt','/dbg/flag','/dbg/flag.txt'):\n"
                "    try:\n"
                "        d=open(p,'rb').read(1)\n"
                "        if d: hits.append(p)\n"
                "    except OSError:\n"
                "        pass\n"
                "print('FLAG_READ_HITS', hits)\n")
            res = pwn_service.run(str(tmp / "run"), str(inp), "target",
                                  "FLAG{p39_test_sentinel}", agent, image=IMAGE,
                                  wall_s=200, exp_name="p39smoke")
            out = res["stdout"]
            self.assertEqual(res["execution_status"], "ok", out)
            self.assertIn("PWNDBG_LOADED True", out)
            self.assertIn("HEAP_OK True", out)
            self.assertIn("POETRY_ERR False", out)
            self.assertIn("FLAG_READ_HITS []", out)  # anti-cheat: flag unreadable by agent


if __name__ == "__main__":
    unittest.main()
