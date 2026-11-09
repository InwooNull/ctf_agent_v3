"""Phase 4.5 regression: a planted or oddly-named script/input must not shadow
stdlib. The harness runs in-container python with `-I`, so the script's /work
directory is not on sys.path.

Skips automatically if the crypto image is not built locally.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solver.crypto_harness import CryptoHarness, CRYPTO_IMAGE  # noqa: E402
from tools import sandbox  # noqa: E402

PROJECT = Path(__file__).resolve().parents[1]
CHALLENGE = PROJECT / "eval" / "datasets" / "dev" / "ch1_encoding"
IMAGE_READY = sandbox.docker_available() and sandbox.image_available(CRYPTO_IMAGE)


@unittest.skipUnless(IMAGE_READY, f"{CRYPTO_IMAGE} not built locally")
class ExecIsolationTest(unittest.TestCase):
    def setUp(self):
        self.store = tempfile.TemporaryDirectory()
        self.addCleanup(self.store.cleanup)

    def _run(self, name, code, timeout=60):
        h = CryptoHarness(f"iso-{name}", CHALLENGE, store_root=self.store.name)
        return h.run_experiment({"name": name, "code": code, "timeout": timeout})

    def test_phase4_inspect_shadow_scenario_now_passes(self):
        # Exact Phase 4 failure: experiment named 'inspect' + sympy (imports stdlib inspect).
        code = ("import sympy\n"
                "print('FACTOR', sympy.factorint(15))\n"
                "print('OK')")
        out = self._run("inspect", code)
        self.assertEqual(out.execution_status, "ok")
        self.assertIn("FACTOR", out.stdout)
        self.assertIn("OK", out.stdout)

    def test_planted_modules_do_not_hijack_imports(self):
        # Plant malicious inspect.py and os.py in cwd (/work), then rely on stdlib.
        code = (
            "open('inspect.py','w').write('raise RuntimeError(\"HIJACKED_inspect\")')\n"
            "open('os.py','w').write('raise RuntimeError(\"HIJACKED_os\")')\n"
            "import sys\n"
            "print('WORK_ON_PATH', any(p in ('', '.', '/work') for p in sys.path))\n"
            "import sympy\n"                       # internally imports stdlib inspect
            "print('FACTOR', sympy.factorint(21))\n"
            "import inspect\n"
            "print('INSPECT_STDLIB', '/usr/local/lib' in inspect.__file__)\n"
            "print('OK')")
        out = self._run("planted", code)
        self.assertEqual(out.execution_status, "ok")
        self.assertNotIn("HIJACKED", out.stdout)
        self.assertIn("WORK_ON_PATH False", out.stdout)
        self.assertIn("INSPECT_STDLIB True", out.stdout)
        self.assertIn("OK", out.stdout)

    def test_isolated_flag_in_argv(self):
        # The container python is invoked with -I (isolated mode).
        h = CryptoHarness("iso-argv", CHALLENGE, store_root=self.store.name)
        h.run_experiment({"name": "probe", "code": "print('x')", "timeout": 60})
        cmds = (h.run_dir / "commands.jsonl").read_text()
        self.assertIn('"-I"', cmds)


if __name__ == "__main__":
    unittest.main()
