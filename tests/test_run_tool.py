import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import run_tool  # noqa: E402
from tools.run_tool import ToolError, run_tool as run  # noqa: E402

# A test-only allowlist that exposes python3/sleep so we can exercise execution
# behaviour. The shipped config/tools.json stays limited to safe utilities.
TEST_TOOLS = {
    "echo": {"bin": "echo", "version_cmd": None, "smoke_cmd": None,
             "deterministic": True, "categories": ["util"], "sandbox_profile": "netns"},
    "base64": {"bin": "base64", "version_cmd": ["base64", "--version"], "smoke_cmd": None,
               "deterministic": True, "categories": ["util"], "sandbox_profile": "netns"},
    "sleep": {"bin": "sleep", "version_cmd": None, "smoke_cmd": None,
              "deterministic": False, "categories": ["util"], "sandbox_profile": "rlimit"},
}


def read_artifact(jail, result, stream="stdout"):
    ref = getattr(result, f"{stream}_ref")
    return (Path(jail) / ref).read_text(errors="replace")


class RunToolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.jail = Path(self.tmp.name)
        self.art = self.jail / "artifacts"

    def tearDown(self):
        self.tmp.cleanup()

    def run_spec(self, spec, **kw):
        return run(spec, jail_root=str(self.jail), artifacts_dir=str(self.art),
                   allowlist=TEST_TOOLS, **kw)

    # ---- requirement 4: allowlist + injection ---------------------------

    def test_tool_not_in_allowlist_rejected(self):
        with self.assertRaises(ToolError):
            run({"tool_id": "python3", "argv": ["python3", "-c", "print(1)"]},
                jail_root=str(self.jail), artifacts_dir=str(self.art))  # real config

    def test_argv_must_be_list_not_shell_string(self):
        with self.assertRaises(ToolError):
            self.run_spec({"tool_id": "echo", "argv": "echo hi; rm -rf /"})

    def test_shell_metacharacters_passed_literally(self):
        payload = [";", "touch", "pwned", "|", "whoami", "$(id)", "`id`", "&&", ">", "out"]
        r = self.run_spec({"tool_id": "echo", "argv": ["echo", *payload]})
        self.assertEqual(r.execution_status, "ok")
        out = read_artifact(self.jail, r)
        self.assertEqual(out.strip(), " ".join(payload))
        # none of the injected commands ran: no side-effect files appeared
        self.assertFalse((self.jail / "pwned").exists())
        self.assertFalse((self.jail / "out").exists())
        self.assertEqual(r.created_files, [])

    # ---- requirement 5: timeout, truncation, reproducibility ------------

    def test_timeout(self):
        r = self.run_spec({"tool_id": "sleep", "argv": ["sleep", "10"], "timeout": 1})
        self.assertEqual(r.execution_status, "timeout")
        self.assertLess(r.duration, 5)

    def test_large_output_truncation_flag(self):
        big = "A" * 200_000
        r = self.run_spec({"tool_id": "base64", "argv": ["base64"], "stdin": big},
                          output_cap=1024)
        self.assertEqual(r.execution_status, "ok")
        self.assertTrue(r.stdout_truncated)
        full = read_artifact(self.jail, r)
        self.assertGreater(len(full), 1024)  # full output preserved in the artifact

    def test_small_output_not_truncated(self):
        r = self.run_spec({"tool_id": "echo", "argv": ["echo", "hi"]})
        self.assertFalse(r.stdout_truncated)

    def test_reproducible_same_result(self):
        spec = {"tool_id": "base64", "argv": ["base64"], "stdin": "reproduce-me"}
        r1 = self.run_spec(dict(spec, execution_id="x1"))
        r2 = self.run_spec(dict(spec, execution_id="x2"))
        self.assertEqual(read_artifact(self.jail, r1), read_artifact(self.jail, r2))
        self.assertEqual(r1.execution_status, r2.execution_status)
        rec1 = run_tool.reproduction_record(spec, r1, allowlist=TEST_TOOLS)
        rec2 = run_tool.reproduction_record(spec, r2, allowlist=TEST_TOOLS)
        self.assertEqual(rec1["argv"], rec2["argv"])
        self.assertEqual(rec1["tool_version"], rec2["tool_version"])

    def test_result_has_no_hypothesis_judgment(self):
        r = self.run_spec({"tool_id": "echo", "argv": ["echo", "x"]})
        d = r.to_dict()
        for forbidden in ("hypothesis_judgment", "judgment", "support", "refute"):
            self.assertNotIn(forbidden, d)
        self.assertIn("execution_status", d)
        self.assertIn("reproducibility_level", d)


if __name__ == "__main__":
    unittest.main()
