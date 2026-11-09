"""Phase 34/35 regression locks: the reproduce-gate code-path fix, pwn per-exp code
persistence, and the Scheduler id-key mapping. Deterministic, no docker."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

_spec = importlib.util.spec_from_file_location("p34", PROJECT_ROOT / "eval" / "p34_rehearsal.py")
p34 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p34)
from orchestrator.scheduler import Scheduler  # noqa: E402


class WinningCodePath(unittest.TestCase):
    """_winning_code must resolve both the misc layout (harness/work/<name>/<name>.py) and the
    pwn layout (harness/exp_code/<name>.py) — the P34 false-negative was looking only at run/work."""
    def _run(self):
        return Path(tempfile.mkdtemp())

    def test_pwn_exp_code_layout(self):
        run = self._run()
        d = run / "harness" / "exp_code"
        d.mkdir(parents=True)
        (d / "e02_e02.py").write_text("print('pwn exploit')")
        code = p34._winning_code(run, "rp_deff37", "rp_deff37-e02_e02")
        self.assertIn("pwn exploit", code)

    def test_misc_work_layout(self):
        run = self._run()
        d = run / "harness" / "work" / "e06_scan2"
        d.mkdir(parents=True)
        (d / "e06_scan2.py").write_text("print('misc decode')")
        code = p34._winning_code(run, "mr_993d5a", "mr_993d5a-e06_scan2")
        self.assertIn("misc decode", code)

    def test_missing_returns_none(self):
        self.assertIsNone(p34._winning_code(self._run(), "x_000000", "x_000000-eNN"))


class PwnExpCodePersisted(unittest.TestCase):
    """The pwn harness must persist each experiment's code (so reproduce can replay it)."""
    def test_harness_writes_exp_code(self):
        src = (PROJECT_ROOT / "solver" / "pwn_service_harness.py").read_text()
        self.assertIn("exp_code", src)
        self.assertIn('(code_dir / f"{name}.py").write_text(spec["code"])', src)


class SchedulerIdMapping(unittest.TestCase):
    """The P34 SET uses 'cid'; building a Scheduler must map cid->id (the KeyError fix)."""
    def test_set_maps_to_scheduler(self):
        for cat, cfg in p34.SET.items():
            items = [{"id": c["cid"], "score": c["score"], "difficulty": c["difficulty"],
                      "est_cost": c["est_cost"]} for c in cfg["challenges"]]
            s = Scheduler(items, global_caps={"experiments": 10 ** 6})
            order = s.order_of_attempt()
            self.assertEqual(sorted(order), sorted(c["cid"] for c in cfg["challenges"]))
            self.assertIsNotNone(s.next())


class RevHoldoutKeyed(unittest.TestCase):
    """Finals premise: the REAL rev holdout (rr_*) is loaded + keyed (scorer_keys_real), not the
    synthetic r7_* set. Vault may be locked; skip gracefully if the keys dir is not readable."""
    def test_real_rev_arena_exists(self):
        arena = PROJECT_ROOT / "arena" / "real_rev"
        self.assertTrue(arena.is_dir())
        rr = [p.name for p in arena.iterdir() if p.name.startswith("rr_")]
        self.assertGreaterEqual(len(rr), 20)


if __name__ == "__main__":
    unittest.main()
