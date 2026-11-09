import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.supervisor import Supervisor, load_settings  # noqa: E402


class ManualClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def challenge(cid, n_experiments=4, duration_s=1):
    return {"id": cid, "name": cid, "description": "rsa", "files": [], "scenario": {"hypotheses": [{
        "statement": "h", "priority_band": "high",
        "experiments": [{"tool": "t", "argv": [str(i)], "judgment": "inconclusive", "duration_s": duration_s}
                        for i in range(n_experiments)],
    }]}}


class BudgetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def settings(self, **budget):
        s = copy.deepcopy(load_settings())
        s["budget"].update(budget)
        return s

    def state(self, sup):
        return json.loads((sup.run_dir / "state.json").read_text())

    def events(self, sup):
        return [json.loads(l) for l in (sup.run_dir / "events.jsonl").read_text().splitlines()]

    def commands(self, sup):
        return (sup.run_dir / "commands.jsonl").read_text().splitlines()

    def test_max_attempts_blocks_and_checkpoints_aborted(self):
        s = self.settings(max_attempts=2)
        sup = Supervisor("r", settings=s, store_root=self.store, clock=ManualClock()).start([challenge("c")])
        self.assertEqual(sup.run(), "aborted")
        self.assertEqual(sup.executions, 2)
        self.assertEqual(len(self.commands(sup)), 2)
        st = self.state(sup)
        self.assertEqual(st["status"], "aborted")
        cp = st["checkpoint"]
        self.assertEqual(cp["budget_spent"]["attempts"], 2)
        self.assertEqual(cp["next_action"]["blocked_by"], "max_attempts")
        self.assertEqual(cp["next_action"]["exp_index"], 2)  # the blocked (never started) experiment
        self.assertEqual(cp["safe_point"]["label"], "aborted")
        self.assertEqual(self.events(sup)[-1]["kind"], "budget_exhausted")

        # resume: still blocked, nothing executes
        again = Supervisor.resume("r", settings=s, store_root=self.store, clock=ManualClock())
        self.assertEqual(again.run(), "aborted")
        self.assertEqual(again.executions, 0)
        self.assertEqual(len(self.commands(again)), 2)

    def test_zero_attempts_blocks_before_first_execution(self):
        sup = Supervisor("r0", settings=self.settings(max_attempts=0), store_root=self.store,
                         clock=ManualClock()).start([challenge("c")])
        self.assertEqual(sup.run(), "aborted")
        self.assertEqual(sup.executions, 0)
        self.assertFalse((sup.run_dir / "commands.jsonl").exists())

    def test_max_rounds_blocks_next_dispatch(self):
        sup = Supervisor("r2", settings=self.settings(max_rounds=1), store_root=self.store,
                         clock=ManualClock()).start([challenge("c1", 1), challenge("c2", 1)])
        self.assertEqual(sup.run(), "aborted")
        st = self.state(sup)
        self.assertIn("c1", st["results"])
        self.assertNotIn("c2", st["results"])
        self.assertEqual(st["checkpoint"]["next_action"],
                         {"kind": "dispatch", "queue_index": 1, "blocked_by": "max_rounds"})
        self.assertEqual(sup.executions, 1)

    def test_time_budget_blocks(self):
        clock = ManualClock()
        sup = Supervisor("r3", settings=self.settings(time_s=8), store_root=self.store,
                         clock=clock).start([challenge("c", 4, duration_s=5)])
        self.assertEqual(sup.run(), "aborted")
        self.assertEqual(sup.executions, 2)  # t=0 ok, t=5 ok, t=10 blocked
        cp = self.state(sup)["checkpoint"]
        self.assertEqual(cp["next_action"]["blocked_by"], "time_s")
        self.assertEqual(cp["budget_spent"]["time_s"], 10.0)


if __name__ == "__main__":
    unittest.main()
