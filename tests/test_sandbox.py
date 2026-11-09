"""Isolation is proven by attempting each bypass and checking it is actually stopped.

Uses a test-only allowlist exposing python3 so the child can try to open sockets,
escape the jail, and blow past resource limits. config/tools.json is untouched.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import sandbox  # noqa: E402
from tools.run_tool import ToolError, run_tool as run  # noqa: E402

PY = {
    # network off -> run under the netns backend when available
    "py_net": {"bin": "python3", "version_cmd": None, "smoke_cmd": None,
               "deterministic": True, "categories": ["util"], "sandbox_profile": "netns"},
    # pure rlimit (no namespace wrapper) so resource limits apply directly to python
    "py": {"bin": "python3", "version_cmd": None, "smoke_cmd": None,
           "deterministic": True, "categories": ["util"], "sandbox_profile": "rlimit"},
}


def read(jail, result, stream="stdout"):
    return (Path(jail) / getattr(result, f"{stream}_ref")).read_text(errors="replace")


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.jail = Path(self.tmp.name)
        self.art = self.jail / "artifacts"

    def tearDown(self):
        self.tmp.cleanup()

    def run_spec(self, spec):
        return run(spec, jail_root=str(self.jail), artifacts_dir=str(self.art), allowlist=PY)

    # ---- requirement 1: outbound network --------------------------------

    def test_outbound_network_blocked_or_reported(self):
        caps = sandbox.capabilities()
        # no "/" anywhere so path-jail validation leaves the code untouched
        code = "import socket;socket.setdefaulttimeout(3);socket.create_connection(('1.1.1.1',53));print('NET_OK')"
        r = self.run_spec({"tool_id": "py_net", "argv": ["py_net", "-I", "-c", code], "timeout": 20})
        if caps["network_block_guaranteed"]:
            self.assertEqual(r.sandbox_profile, sandbox.PROFILE_NETNS)
            self.assertTrue(r.network_guaranteed)
            self.assertNotEqual(r.execution_status, "ok")
            self.assertNotIn("NET_OK", read(self.jail, r))
            self.assertIn("unreachable", read(self.jail, r, "stderr").lower())
        else:
            # Honest reporting: the layer must not claim a guarantee it cannot keep,
            # and such a tool would only ever be an allowlisted safe one.
            self.assertFalse(r.network_guaranteed)
            self.assertEqual(r.sandbox_profile, sandbox.PROFILE_RLIMIT)

    # ---- requirement 2: path jail / traversal ---------------------------

    def test_relative_traversal_rejected(self):
        with self.assertRaises(ToolError):
            self.run_spec({"tool_id": "py", "argv": ["py", "../escape.py"]})

    def test_absolute_path_outside_jail_rejected(self):
        with self.assertRaises(ToolError):
            self.run_spec({"tool_id": "py", "argv": ["py", "/etc/passwd"]})

    def test_cwd_outside_jail_rejected(self):
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(ToolError):
                run({"tool_id": "py", "argv": ["py", "-c", "pass"], "cwd": other},
                    jail_root=str(self.jail), artifacts_dir=str(self.art), allowlist=PY)

    def test_path_inside_jail_allowed(self):
        (self.jail / "inside.txt").write_text("hi")
        r = self.run_spec({"tool_id": "py", "argv": ["py", "-I", "-c", "print(1)"]})
        self.assertEqual(r.execution_status, "ok")

    # ---- requirement 3: resource limits ---------------------------------

    def test_cpu_limit_aborts(self):
        code = "x=0\nwhile True:x+=1"
        r = self.run_spec({"tool_id": "py", "argv": ["py", "-I", "-c", code],
                           "resource_limits": {"cpu_s": 1}, "timeout": 30})
        self.assertEqual(r.execution_status, "aborted")  # SIGXCPU, negative return code
        self.assertTrue(r.return_code < 0)

    def test_memory_limit_stops_allocation(self):
        code = "b=bytearray(800*1024*1024);print('ALLOC_OK')"
        r = self.run_spec({"tool_id": "py", "argv": ["py", "-I", "-c", code],
                           "resource_limits": {"mem_bytes": 64 * 1024 * 1024}, "timeout": 30})
        self.assertNotEqual(r.execution_status, "ok")
        self.assertNotIn("ALLOC_OK", read(self.jail, r))

    def test_file_size_limit_stops_write(self):
        # write a file far larger than the limit; the write must be capped
        code = "f=open('big.bin','wb')\nf.write(b'x'*(50*1024*1024))\nf.close()\nprint('WROTE_ALL')"
        r = self.run_spec({"tool_id": "py", "argv": ["py", "-I", "-c", code],
                           "resource_limits": {"file_bytes": 100_000}, "timeout": 30})
        self.assertNotEqual(r.execution_status, "ok")
        self.assertNotIn("WROTE_ALL", read(self.jail, r))
        big = self.jail / "big.bin"
        if big.exists():
            self.assertLessEqual(big.stat().st_size, 100_000 + 4096)


if __name__ == "__main__":
    unittest.main()
