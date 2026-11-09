"""Container isolation proven by attempting each bypass *inside the container*.

Skipped automatically if the docker backend + configured local image are not
ready (no pull is ever attempted). Uses a test-only allowlist whose `pycode`
tool is marked untrusted and bound to the container profile.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import sandbox  # noqa: E402
from tools.run_tool import ToolError, run_tool as run  # noqa: E402

CAPS = sandbox.capabilities()
CONTAINER_READY = CAPS["container_backend_ready"]

ALLOW = {
    # untrusted arbitrary python, only ever allowed inside the container backend
    "pycode": {"bin": "python3", "version_cmd": None, "smoke_cmd": None,
               "deterministic": True, "trust": "untrusted", "categories": ["exec"],
               "sandbox_profile": "container"},
    "idtool": {"bin": "id", "version_cmd": None, "smoke_cmd": None,
               "deterministic": True, "trust": "untrusted", "categories": ["exec"],
               "sandbox_profile": "container"},
}


def read(jail, result, stream="stdout"):
    return (Path(jail) / getattr(result, f"{stream}_ref")).read_text(errors="replace")


@unittest.skipUnless(CONTAINER_READY,
                     "docker backend / configured image not available locally (no pull attempted)")
class ContainerSandboxTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.jail = Path(self.tmp.name)
        self.art = self.jail / "artifacts"

    def tearDown(self):
        self.tmp.cleanup()

    def py(self, code, **spec):
        base = {"tool_id": "pycode", "argv": ["pycode", "-I", "-c", code], "timeout": 60}
        base.update(spec)
        return run(base, jail_root=str(self.jail), artifacts_dir=str(self.art), allowlist=ALLOW)

    # ---- requirement 1: network --------------------------------------------

    def test_network_blocked(self):
        code = "import socket;socket.setdefaulttimeout(3);socket.create_connection(('1.1.1.1',53));print('NET_OK')"
        r = self.py(code)
        self.assertEqual(r.sandbox_profile, "container")
        self.assertNotEqual(r.execution_status, "ok")
        self.assertNotIn("NET_OK", read(self.jail, r))

    def test_dns_blocked(self):
        code = "import socket;print(socket.gethostbyname('example.com'))"
        r = self.py(code)
        self.assertNotEqual(r.execution_status, "ok")

    # ---- requirement 2: host FS not exposed --------------------------------

    def test_host_marker_not_visible(self):
        # a marker that exists on the host but is NOT in the mounted workdir
        marker = Path.home() / "ctf_agent_v3" / ".host_secret_marker"
        created = False
        if not marker.exists():
            marker.write_text("HOST_SECRET_VALUE")
            created = True
        try:
            code = ("import glob,os\n"
                    "hits=[p for p in glob.glob('/**/.host_secret_marker',recursive=True)]\n"
                    "print('HITS',hits)\n"
                    "print('CWD',os.listdir('.'))")
            r = self.py(code)
            out = read(self.jail, r)
            self.assertNotIn("HOST_SECRET_VALUE", out)
            self.assertNotIn(".host_secret_marker", out)
        finally:
            if created:
                marker.unlink()

    def test_etc_passwd_is_container_not_host(self):
        # /etc/passwd exists but belongs to the container image (Debian), not the host
        r = self.py("print(open('/etc/passwd').read())")
        out = read(self.jail, r)
        self.assertEqual(r.execution_status, "ok")
        self.assertNotIn("inwoo", out)  # host username must not appear

    # ---- requirement 3: write isolation ------------------------------------

    def test_root_fs_write_blocked(self):
        r = self.py("open('/root_escape','w').write('x');print('WROTE')")
        self.assertNotEqual(r.execution_status, "ok")
        self.assertNotIn("WROTE", read(self.jail, r))

    def test_workdir_write_allowed_and_persists(self):
        r = self.py("open('out.txt','w').write('hello');print('OK')")
        self.assertEqual(r.execution_status, "ok")
        self.assertIn("OK", read(self.jail, r))
        self.assertIn("out.txt", r.created_files)
        self.assertEqual((self.jail / "out.txt").read_text(), "hello")

    # ---- requirement 4: resources ------------------------------------------

    def test_memory_limit(self):
        r = self.py("b=bytearray(600*1024*1024);print('ALLOC_OK')")
        self.assertIn(r.execution_status, ("aborted", "error"))
        self.assertNotIn("ALLOC_OK", read(self.jail, r))

    def test_cpu_bound_hits_wall_timeout(self):
        r = self.py("x=0\nwhile True:x+=1", timeout=3)
        self.assertEqual(r.execution_status, "timeout")

    def test_fork_bomb_capped_by_pids_limit(self):
        code = ("import os,sys\n"
                "n=0\n"
                "try:\n"
                "  while n<5000:\n"
                "    pid=os.fork()\n"
                "    if pid==0: os._exit(0)\n"
                "    n+=1\n"
                "except OSError:\n"
                "  print('FORK_BLOCKED',n); sys.exit(0)\n"
                "print('FORKED_ALL',n)")
        r = self.py(code, timeout=30)
        out = read(self.jail, r)
        self.assertNotIn("FORKED_ALL", out)

    # ---- requirement 5: privileges -----------------------------------------

    def test_runs_as_non_root(self):
        r = run({"tool_id": "idtool", "argv": ["idtool"], "timeout": 30},
                jail_root=str(self.jail), artifacts_dir=str(self.art), allowlist=ALLOW)
        self.assertEqual(r.execution_status, "ok")
        out = read(self.jail, r)
        self.assertNotIn("uid=0(root)", out)
        self.assertIn("uid=", out)

    # ---- requirement 6: lifecycle (--rm) -----------------------------------

    def test_container_is_removed_after_run(self):
        r = self.py("print('done')", execution_id="lifecycle-check")
        name = "ctfagent_pycode-lifecycle-check"
        ps = subprocess.run(["docker", "ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"],
                            capture_output=True, text=True, timeout=20)
        self.assertEqual(ps.stdout.strip(), "", "container was not auto-removed")


class ContainerPolicyTest(unittest.TestCase):
    """Policy holds regardless of whether docker is present."""

    def test_untrusted_refused_without_container_profile(self):
        bad = {"evil": {"bin": "python3", "version_cmd": None, "smoke_cmd": None,
                        "deterministic": True, "trust": "untrusted", "categories": ["exec"],
                        "sandbox_profile": "netns"}}  # untrusted but NOT container
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ToolError):
                run({"tool_id": "evil", "argv": ["evil", "-c", "print(1)"]},
                    jail_root=d, artifacts_dir=str(Path(d) / "a"), allowlist=bad)


if __name__ == "__main__":
    unittest.main()
