import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import probe  # noqa: E402

UNIVERSAL = {
    "echo": {"bin": "echo", "version_cmd": None, "smoke_cmd": ["echo", "ping"],
             "smoke_expect": "ping", "deterministic": True, "categories": ["util"],
             "sandbox_profile": "netns"},
    "cat": {"bin": "cat", "version_cmd": ["cat", "--version"], "smoke_cmd": None,
            "deterministic": True, "categories": ["util"], "sandbox_profile": "netns"},
    "file": {"bin": "file", "version_cmd": ["file", "--version"], "smoke_cmd": ["file", "-b", "-"],
             "smoke_stdin": "\x7fELF", "deterministic": True, "categories": ["forensics"],
             "sandbox_profile": "netns"},
    "definitely_absent_tool_xyz": {"bin": "definitely_absent_tool_xyz", "version_cmd": None,
                                   "smoke_cmd": ["definitely_absent_tool_xyz"], "deterministic": True,
                                   "categories": ["util"], "sandbox_profile": "netns"},
}


class ProbeTest(unittest.TestCase):
    def test_isolation_report_shape(self):
        caps = probe.probe_isolation()
        for k in ("docker", "unshare_netns", "rlimit", "network_block_guaranteed"):
            self.assertIn(k, caps)
            self.assertIsInstance(caps[k], bool)

    def test_present_and_smoke_pass(self):
        r = probe.probe_tool("echo", UNIVERSAL["echo"])
        self.assertTrue(r["present"])
        self.assertTrue(r["smoke_ok"])
        self.assertTrue(r["ready"])

    @unittest.skipIf(shutil.which("file") is None, "file not installed")
    def test_version_and_smoke_with_stdin(self):
        r = probe.probe_tool("file", UNIVERSAL["file"])
        self.assertTrue(r["present"])
        self.assertTrue(r["ready"])
        self.assertTrue(r["version"])  # non-empty version string

    def test_presence_only_tool(self):
        r = probe.probe_tool("cat", UNIVERSAL["cat"])
        self.assertTrue(r["present"])
        self.assertTrue(r["ready"])  # no smoke_cmd -> presence is enough

    def test_absent_tool_not_ready(self):
        r = probe.probe_tool("definitely_absent_tool_xyz", UNIVERSAL["definitely_absent_tool_xyz"])
        self.assertFalse(r["present"])
        self.assertFalse(r["ready"])

    def test_probe_all_pipeline(self):
        report = probe.probe_all(allowlist=UNIVERSAL)
        self.assertIn("isolation", report)
        self.assertEqual(set(report["tools"]), set(UNIVERSAL))
        self.assertTrue(report["tools"]["echo"]["ready"])
        self.assertFalse(report["tools"]["definitely_absent_tool_xyz"]["ready"])


if __name__ == "__main__":
    unittest.main()
