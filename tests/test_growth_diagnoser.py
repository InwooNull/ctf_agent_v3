"""Phase 44b: the Diagnoser — rule-table-first classification, the fail-safe asymmetry
(ambiguous -> NON-AUTO), and FWS exclusion from the experience-promotion success set.

Vault-free, token-free: the residual `judge` is a deterministic stub, never a real model
call; every crisp case is decided by the rule table with no judge at all.
"""
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth.loop import RunOutcome  # noqa: E402
from growth.diagnoser import (  # noqa: E402
    Diagnoser, promotable_successes, is_auto, DISPOSITION, write_requests)


def run(cid, outcome="GIVE_UP", solved=False, **signals):
    return RunOutcome(cid=cid, outcome=outcome, solved=solved, signals=signals)


class TestRuleTable(unittest.TestCase):
    def setUp(self):
        self.dx = Diagnoser(judge=None)   # no judge -> residual always fails safe

    def one(self, r):
        return self.dx.diagnose_one(r)

    def test_cyber_block_is_log_once_nonauto(self):
        d = self.one(run("c", cyber_blocked=True))
        self.assertEqual(d.bucket, "cyber_blocked")
        self.assertEqual(d.disposition, "LOG_ONCE")
        self.assertFalse(d.actionable)

    def test_harness_fault_is_human_gate(self):
        for sig in ("harness_error", "deploy_fault", "recv_cap_hit"):
            d = self.one(run("c", **{sig: True}))
            self.assertEqual(d.bucket, "harness_bug", sig)
            self.assertFalse(d.actionable)

    def test_tool_gap_from_signal_or_selfreport(self):
        self.assertEqual(self.one(run("c", tool_missing=True)).bucket, "tool_gap")
        self.assertEqual(self.one(run("c", give_up_kind="tool")).bucket, "tool_gap")
        self.assertFalse(self.one(run("c", tool_missing=True)).actionable)

    def test_budget_is_auto_only_when_tools_worked(self):
        # budget exhausted WITH ok experiments -> AUTO budget
        d = self.one(run("c", outcome="BUDGET_EXHAUSTED", budget_exhausted=True, n_exp_ok=4))
        self.assertEqual(d.bucket, "budget")
        self.assertTrue(d.actionable)
        # budget 'hit' but nothing ran ok -> NOT budget; residual -> fail-safe ambiguous
        d2 = self.one(run("c", outcome="BUDGET_EXHAUSTED", budget_exhausted=True, n_exp_ok=0))
        self.assertEqual(d2.bucket, "ambiguous")
        self.assertFalse(d2.actionable)

    def test_nonauto_signal_beats_cooccurring_auto_signal(self):
        # tooling 'worked' (budget signal) BUT a tool was missing -> tool_gap must win,
        # because self-modifying the cheatsheet when a tool is absent is the unsafe error.
        d = self.one(run("c", budget_exhausted=True, n_exp_ok=5, tool_missing=True))
        self.assertEqual(d.bucket, "tool_gap")
        self.assertFalse(d.actionable)


class TestFailSafeAsymmetry(unittest.TestCase):
    """REQUIRED: an ambiguous case must land NON-AUTO (never self-modify when unsure)."""

    def test_no_judge_residual_is_ambiguous_nonauto(self):
        dx = Diagnoser(judge=None)
        d = dx.diagnose_one(run("c", give_up_kind="analysis"))
        self.assertEqual(d.bucket, "ambiguous")
        self.assertFalse(is_auto(d.bucket))
        self.assertEqual(d.source, "fail-safe")

    def test_low_confidence_auto_verdict_demoted_to_nonauto(self):
        # the judge WANTS an AUTO bucket but is not confident -> must be refused -> ambiguous
        dx = Diagnoser(judge=lambda s, e: ("knowledge_gap", 0.5))
        d = dx.diagnose_one(run("c", give_up_kind="analysis"))
        self.assertEqual(d.bucket, "ambiguous")
        self.assertFalse(d.actionable)
        self.assertEqual(d.source, "fail-safe")

    def test_high_confidence_auto_verdict_accepted(self):
        dx = Diagnoser(judge=lambda s, e: ("knowledge_gap", 0.9))
        d = dx.diagnose_one(run("c", give_up_kind="analysis"))
        self.assertEqual(d.bucket, "knowledge_gap")
        self.assertTrue(d.actionable)
        self.assertEqual(d.source, "judge")

    def test_nonauto_verdict_accepted_at_any_confidence(self):
        # a judge's NON-AUTO call is taken even when low-confidence (erring toward safe)
        dx = Diagnoser(judge=lambda s, e: ("harness_bug", 0.2))
        d = dx.diagnose_one(run("c", give_up_kind="analysis"))
        self.assertEqual(d.bucket, "harness_bug")
        self.assertFalse(d.actionable)

    def test_unknown_or_crashing_judge_fails_safe(self):
        self.assertEqual(Diagnoser(judge=lambda s, e: ("nonsense", 0.99))
                         .diagnose_one(run("c")).bucket, "ambiguous")
        def boom(s, e):
            raise RuntimeError("judge exploded")
        self.assertEqual(Diagnoser(judge=boom).diagnose_one(run("c")).bucket, "ambiguous")


class TestNonAutoNeverLeaksToAuto(unittest.TestCase):
    """Lock: tool_gap / harness_bug / human_grade / cyber_blocked are never actionable."""

    def test_gated_buckets_not_actionable(self):
        dx = Diagnoser(judge=None)
        cases = {
            "tool_gap": run("c", tool_missing=True),
            "harness_bug": run("c", harness_error=True),
            "human_grade": run("c", human_grade_hint=True),
            "cyber_blocked": run("c", cyber_blocked=True),
        }
        for want, r in cases.items():
            d = dx.diagnose_one(r)
            self.assertEqual(d.bucket, want)
            self.assertFalse(d.actionable, f"{want} must NOT be actionable")
            self.assertNotIn(d.bucket, [b for b in DISPOSITION if is_auto(b)])


class TestFwsExclusion(unittest.TestCase):
    """REQUIRED: an FWS trajectory is excluded from the experience-promotion success set."""

    def test_fws_excluded_even_if_marked_solved(self):
        runs = [
            RunOutcome("ok1", outcome="SOLVED", solved=True),
            RunOutcome("fws_by_verdict", outcome="FLAG_WITHOUT_SOLUTION", solved=False),
            # defensive: an upstream bug set solved=True on an FWS run -> still excluded
            RunOutcome("fws_but_solved_flag", outcome="SOLVED", solved=True, signals={"fws": True}),
        ]
        good = [r.cid for r in promotable_successes(runs)]
        self.assertEqual(good, ["ok1"])

    def test_fws_tagged_and_routed_nonauto(self):
        dx = Diagnoser(judge=None)
        d = dx.diagnose_one(RunOutcome("c", outcome="FLAG_WITHOUT_SOLUTION", solved=False))
        self.assertTrue(d.fws)
        self.assertEqual(d.bucket, "fws")
        self.assertFalse(d.actionable)


class TestRequestsLog(unittest.TestCase):
    def test_human_gate_written_auto_skipped_cyber_dedup(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "requests.md"
            dx = Diagnoser(judge=None)
            diags = dx.diagnose([
                run("a", tool_missing=True),                       # HUMAN_GATE
                run("b", outcome="BUDGET_EXHAUSTED", budget_exhausted=True, n_exp_ok=3),  # AUTO (skip)
                run("c", cyber_blocked=True),                      # LOG_ONCE
            ])
            wrote1 = write_requests(diags, p)
            self.assertEqual({d["cid"] for d in wrote1}, {"a", "c"})   # AUTO 'b' not logged
            # logging the same cyber block again does NOT duplicate it
            wrote2 = write_requests(dx.diagnose([run("c", cyber_blocked=True)]), p)
            self.assertEqual(wrote2, [])
            self.assertEqual(p.read_text().count("cyber_blocked :: c"), 1)


if __name__ == "__main__":
    unittest.main()
