"""Phase 46b: the diagnoser distinguishes genuine budget-shortfall from a stalled/looping
approach, test-locked on the THREE real failure traces from the Phase-45 run #1.

Only SIGNAL FIELDS are used (tests/fixtures/p45_run1_signals.json) — no flag, no scorer
key, no transcript. The two impl-bug / repeated-error traces must reclassify to `approach`
(a knowledge pivot, NOT more budget); the one genuinely-progressing trace stays `budget`.
"""
import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth.loop import RunOutcome  # noqa: E402
from growth.diagnoser import Diagnoser, AUTO_SURFACE, is_auto  # noqa: E402

FIX = json.loads((PROJECT_ROOT / "tests" / "fixtures" / "p45_run1_signals.json").read_text())


def _run(cid):
    return RunOutcome(cid=cid, outcome="GIVE_UP", solved=False, category="misc", signals=FIX[cid])


class TestRun1Reclassification(unittest.TestCase):
    def setUp(self):
        self.dx = Diagnoser(judge=None)

    def test_impl_bug_traces_are_approach_not_budget(self):
        for cid in ("mr_42745d", "mr_8c08a5"):          # give_up=impl / repeated errors
            d = self.dx.diagnose_one(_run(cid))
            self.assertEqual(d.bucket, "approach", cid)
            self.assertTrue(d.actionable)
            self.assertEqual(d.source, "rule")
            self.assertNotEqual(d.bucket, "budget", f"{cid} must NOT be auto-labelled budget")

    def test_genuine_progress_trace_stays_budget(self):
        d = self.dx.diagnose_one(_run("mr_60057e"))      # give_up=analysis, monotonic progress
        self.assertEqual(d.bucket, "budget")
        self.assertTrue(d.actionable)
        self.assertEqual(d.source, "rule")

    def test_three_traces_split_two_approach_one_budget(self):
        got = {cid: self.dx.diagnose_one(_run(cid)).bucket for cid in FIX}
        self.assertEqual(sorted(b for b in got.values()), ["approach", "approach", "budget"])


class TestBudgetVsStalledRule(unittest.TestCase):
    def setUp(self):
        self.dx = Diagnoser(judge=None)

    def _b(self, **sig):
        return self.dx.diagnose_one(RunOutcome("c", "GIVE_UP", False, signals=sig)).bucket

    def test_stalled_signals_force_approach(self):
        self.assertEqual(self._b(budget_exhausted=True, n_exp_ok=11, give_up_kind="impl"), "approach")
        self.assertEqual(self._b(budget_exhausted=True, n_exp_ok=11, stalled=True), "approach")
        self.assertEqual(self._b(budget_exhausted=True, n_exp_ok=9, repeated_error_class=True), "approach")
        self.assertEqual(self._b(budget_exhausted=True, n_exp_ok=9, no_observation_growth=True), "approach")

    def test_progressing_budget_stays_budget(self):
        self.assertEqual(self._b(budget_exhausted=True, n_exp_ok=11, give_up_kind="analysis"), "budget")

    def test_budget_hit_no_ok_not_stalled_is_residual_ambiguous(self):
        # unchanged fail-safe: nothing ran ok and not stalled -> non-AUTO ambiguous
        self.assertEqual(self._b(budget_exhausted=True, n_exp_ok=0), "ambiguous")


class TestAutoSurfaceSeparation(unittest.TestCase):
    """approach's AUTO fix is a KNOWLEDGE edit (skill), distinct from budget's config bump."""

    def test_surfaces_defined_and_distinct(self):
        self.assertEqual(AUTO_SURFACE["approach"], "skill")
        self.assertEqual(AUTO_SURFACE["budget"], "budget")
        self.assertNotEqual(AUTO_SURFACE["approach"], AUTO_SURFACE["budget"])
        self.assertEqual(AUTO_SURFACE["knowledge_gap"], "skill")
        self.assertEqual(AUTO_SURFACE["experience_gap"], "experience")
        for b in ("approach", "budget", "knowledge_gap", "experience_gap"):
            self.assertTrue(is_auto(b))


if __name__ == "__main__":
    unittest.main()
