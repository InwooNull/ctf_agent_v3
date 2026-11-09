"""Phase 41 tests: the opt-in persisted-/work harness option and the p41 CLI routing.
Structural/route checks are docker-free; the cross-experiment persistence proof (and that the
default stays isolated) is gated on docker + image 0.1.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver.rev_harness import RevHarness       # noqa: E402
from solver.crypto_harness import CryptoHarness  # noqa: E402
from tools import sandbox                         # noqa: E402

IMG01 = "ctfagent-rev:0.1"


class TestPersistDefaultOff(unittest.TestCase):
    def test_crypto_harness_defaults_persist_off(self):
        # a fresh harness must default to isolated per-experiment /work (no lane behavior change)
        tmp = tempfile.mkdtemp()
        h = CryptoHarness.__new__(CryptoHarness)  # no container needed; just the attribute default
        self.assertFalse(getattr(h, "persist_work", False))


class TestP41Routing(unittest.TestCase):
    def _load(self, run_id):
        sys.argv = ["rev_cli.py", run_id, "status"]
        spec = importlib.util.spec_from_file_location("rev_cli_probe41", PROJECT_ROOT / "arena" / "rev_cli.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_c0(self):
        m = self._load("p41c0-r1-rr_df0262")
        self.assertEqual(m.REV_IMAGE_ROUTE, IMG01)
        self.assertFalse(m.ANGR_EXPOSED)
        self.assertTrue(m.PERSIST_WORK)
        self.assertEqual(m.REV_MEM, "2g")
        self.assertEqual(m.REV_BUDGET, {"max_experiments": 20, "wall_s": 3000, "exp_timeout_s": 300})
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p41_rev", "c0"))

    def test_c1(self):
        m = self._load("p41c1-r1-rr_df0262")
        self.assertEqual(m.REV_IMAGE_ROUTE, "ctfagent-rev:0.2")
        self.assertTrue(m.ANGR_EXPOSED)
        self.assertTrue(m.PERSIST_WORK)
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p41_rev", "c1"))

    def test_c0_c1_same_budget(self):
        self.assertEqual(self._load("p41c0-r1-rr_df0262").REV_BUDGET,
                         self._load("p41c1-r1-rr_df0262").REV_BUDGET)

    def test_pre_p41_routes_not_persisted(self):
        for rid in ("p40c0-r1-rr_df0262", "p40c1-r1-rr_df0262", "p36rv-r1-x"):
            self.assertFalse(self._load(rid).PERSIST_WORK, rid)

    def tearDown(self):
        sys.argv = ["rev_cli.py", ""]


@unittest.skipUnless(sandbox.docker_available() and sandbox.image_available(IMG01),
                     f"{IMG01} / docker not available")
class TestPersistEndToEnd(unittest.TestCase):
    CHAL = str(PROJECT_ROOT / "arena" / "real_rev" / "rr_df0262")

    def _h(self, persist):
        h = RevHarness("t", self.CHAL, store_root=tempfile.mkdtemp(), image=IMG01,
                       budget={"time_s": 300, "max_attempts": 5})
        h.persist_work = persist
        return h

    def test_persisted_work_survives_between_experiments(self):
        h = self._h(True)
        h.run_experiment({"name": "e01_w", "code": "open('/work/b','w').write('x'); print('w')", "timeout": 60})
        o = h.run_experiment({"name": "e02_r",
                              "code": "import os; print('SEEN' if os.path.exists('/work/b') else 'GONE')",
                              "timeout": 60})
        self.assertIn("SEEN", o.stdout)

    def test_default_work_is_isolated(self):
        h = self._h(False)
        h.run_experiment({"name": "e01_w", "code": "open('/work/b','w').write('x'); print('w')", "timeout": 60})
        o = h.run_experiment({"name": "e02_r",
                              "code": "import os; print('GONE' if not os.path.exists('/work/b') else 'LEAK')",
                              "timeout": 60})
        self.assertIn("GONE", o.stdout)


if __name__ == "__main__":
    unittest.main()
