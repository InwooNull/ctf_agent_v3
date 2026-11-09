"""Phase-29 orchestrator policy tests (deterministic): stop-loss, reallocation,
decoy screening, and reproduce-before-submit. No live, no LLM."""
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.stoploss import StopLoss, CONTINUE, RAISE_ONCE, STOP  # noqa: E402
from orchestrator.scheduler import Scheduler                            # noqa: E402
from orchestrator import triage                                         # noqa: E402
from connector.submit_gate import (                                     # noqa: E402
    SubmitGate, DecoyRejected, ReproductionFailed, NotAuthorized,
)
from connector.ctfd_client import RateLimited                           # noqa: E402
from schemas.records import Candidate                                   # noqa: E402


class FakeClient:
    def __init__(self, correct):
        self.correct, self.calls = correct, 0
    def submit_flag(self, cid, flag):
        self.calls += 1
        return ("correct" if flag == self.correct else "incorrect"), "ok"


def _verified(v, refs=("A1",)):
    return Candidate(value=v, confidence=0.9, evidence_refs=list(refs), status="VERIFIED")


# ---- 1) stop-loss --------------------------------------------------------
class StopLossPolicy(unittest.TestCase):
    def test_no_progress_stops_without_chain(self):
        sl = StopLoss(caps={"experiments": 100}, no_progress_k=3)
        for _ in range(2):
            sl.record_round(info_gain=0)
            self.assertEqual(sl.decide(has_verified_chain=False), CONTINUE)
        sl.record_round(info_gain=0)  # 3rd stalled round
        self.assertEqual(sl.decide(has_verified_chain=False), STOP)

    def test_progress_resets_stall(self):
        sl = StopLoss(no_progress_k=2)
        sl.record_round(0); sl.record_round(5)  # gain breaks the stall
        self.assertEqual(sl.trailing_stall(), 0)
        self.assertEqual(sl.decide(False), CONTINUE)

    def test_verified_chain_raises_once_then_stops(self):
        sl = StopLoss(caps={"experiments": 4}, no_progress_k=2, raise_factor=2.0)
        for _ in range(2):
            sl.record_round(info_gain=0, experiments=1)
        # stalled with a verified chain -> one budget raise (near-miss recovery)
        self.assertEqual(sl.decide(has_verified_chain=True), RAISE_ONCE)
        self.assertTrue(sl.raised)
        self.assertEqual(sl.caps["experiments"], 8)       # raised
        self.assertEqual(sl.decide(has_verified_chain=True), CONTINUE)  # fresh window
        # stall again -> now it stops for good (only one raise allowed)
        for _ in range(2):
            sl.record_round(info_gain=0)
        self.assertEqual(sl.decide(has_verified_chain=True), STOP)

    def test_over_budget_triggers(self):
        sl = StopLoss(caps={"experiments": 2}, no_progress_k=99)
        sl.record_round(info_gain=1, experiments=1)
        self.assertEqual(sl.decide(False), CONTINUE)
        sl.record_round(info_gain=1, experiments=1)   # now spent==cap
        self.assertEqual(sl.over_budget(), "experiments")
        self.assertEqual(sl.decide(False), STOP)

    def test_checkpoint_roundtrip(self):
        sl = StopLoss(caps={"experiments": 5, "wall_s": 10.0}, no_progress_k=2)
        sl.record_round(info_gain=0, experiments=2, wall_s=3.0)
        d = sl.to_dict()
        sl2 = StopLoss.from_dict(d)
        self.assertEqual(sl2.to_dict(), d)
        self.assertEqual(sl2.spent["experiments"], 2)


# ---- 2) reallocation -----------------------------------------------------
class SchedulerPolicy(unittest.TestCase):
    def _queue(self):
        return [
            {"id": "a", "score": 100, "difficulty": "hard", "est_cost": 4.0},  # ev 25 /4 = 6.25
            {"id": "b", "score": 100, "difficulty": "easy", "est_cost": 2.0},  # ev 100/2 = 50
            {"id": "c", "score": 50, "difficulty": "med", "est_cost": 1.0},    # ev 25 /1 = 25
        ]

    def test_order_by_expected_value_per_cost(self):
        s = Scheduler(self._queue())
        self.assertEqual(s.order_of_attempt(), ["b", "c", "a"])
        self.assertEqual(s.next(), "b")

    def test_moves_to_next_when_done(self):
        s = Scheduler(self._queue())
        self.assertEqual(s.next(), "b")
        s.mark_done("b", "stopped")
        self.assertEqual(s.next(), "c")
        s.mark_done("c", "solved")
        self.assertEqual(s.next(), "a")
        s.mark_done("a", "stopped")
        self.assertIsNone(s.next())

    def test_global_cap_halts_selection(self):
        s = Scheduler(self._queue(), global_caps={"experiments": 10})
        s.record_spend(experiments=10)
        self.assertEqual(s.global_exhausted(), "experiments")
        self.assertIsNone(s.next())

    def test_difficulty_feedback_changes_priority(self):
        s = Scheduler([{"id": "x", "score": 100, "difficulty": "easy", "est_cost": 1.0},
                       {"id": "y", "score": 100, "difficulty": "easy", "est_cost": 1.0}])
        self.assertEqual(s.order_of_attempt()[0], "x")  # tie -> queue order
        s.update_difficulty("x", "harder")              # x now 'med' -> lower priority
        self.assertEqual(s.next(), "y")

    def test_tie_break_is_deterministic(self):
        s = Scheduler([{"id": "p", "score": 10, "difficulty": "med", "est_cost": 1.0},
                       {"id": "q", "score": 10, "difficulty": "med", "est_cost": 1.0}])
        self.assertEqual(s.next(), "p")


# ---- 3) decoy ------------------------------------------------------------
class Decoy(unittest.TestCase):
    def test_sample_flag_is_decoy(self):
        self.assertTrue(triage.is_decoy("FLAG{THIS IS A SAMPLE FLAG}", evidence_refs=["A1"]))
        self.assertTrue(triage.is_decoy("flag{sample_flag}", evidence_refs=["A1"]))

    def test_no_evidence_is_decoy(self):
        self.assertTrue(triage.is_decoy("FLAG{looks_real_but_guessed}", evidence_refs=[]))

    def test_real_flag_with_evidence_ok(self):
        self.assertFalse(triage.is_decoy("acdc2026{real}", evidence_refs=["A1"]))

    def test_first_pass_finds_and_labels(self):
        d = Path(tempfile.mkdtemp())
        (d / "flag.txt").write_text("FLAG{d34db33fd34db33f}\n")
        (d / "readme.md").write_text("example: FLAG{THIS_IS_A_SAMPLE_FLAG}")
        hits = triage.first_pass(d, flag_re=r"FLAG\{[^}]+\}")
        by_val = {h["value"]: h for h in hits}
        self.assertIn("FLAG{d34db33fd34db33f}", by_val)
        self.assertTrue(by_val["FLAG{d34db33fd34db33f}"]["leaky_name"])
        self.assertFalse(by_val["FLAG{d34db33fd34db33f}"]["decoy"])
        self.assertTrue(by_val["FLAG{THIS_IS_A_SAMPLE_FLAG}"]["decoy"])


# ---- 4) reproduce-before-submit -----------------------------------------
class ReproduceGate(unittest.TestCase):
    def _gate(self, correct, reproducer=None, decoy_check=triage.is_decoy):
        return SubmitGate.for_orchestrator(
            FakeClient(correct), log_path=Path(tempfile.mkdtemp()) / "s.jsonl",
            decoy_check=decoy_check, reproducer=reproducer)

    def test_reproduction_success_submits(self):
        flag = "acdc2026{win}"
        reps = {"n": 0}
        def good(cid, cand):
            reps["n"] += 1
            return {"ok": True, "flag": cand.value, "evidence": "fresh-run-A"}
        gate = self._gate(flag, reproducer=good)
        self.assertEqual(gate.submit_candidate("c1", _verified(flag))[0], "correct")
        self.assertEqual(reps["n"], 1)   # reproduced before the one submit

    def test_reproduction_failure_blocks_submit(self):
        flag = "acdc2026{win}"
        def bad(cid, cand):
            return {"ok": False, "flag": None}
        gate = self._gate(flag, reproducer=bad)
        with self.assertRaises(ReproductionFailed):
            gate.submit_candidate("c1", _verified(flag))
        self.assertEqual(gate.client.calls, 0)  # never reached the network

    def test_reproduction_mismatch_blocks(self):
        gate = self._gate("acdc2026{win}",
                          reproducer=lambda cid, c: {"ok": True, "flag": "acdc2026{other}"})
        with self.assertRaises(ReproductionFailed):
            gate.submit_candidate("c1", _verified("acdc2026{win}"))
        self.assertEqual(gate.client.calls, 0)

    def test_decoy_rejected_before_network(self):
        gate = self._gate("x", reproducer=lambda cid, c: {"ok": True, "flag": c.value})
        decoy = _verified("FLAG{THIS IS A SAMPLE FLAG}")
        with self.assertRaises(DecoyRejected):
            gate.submit_candidate("c1", decoy)
        self.assertEqual(gate.client.calls, 0)

    def test_subagent_still_blocked_with_gates(self):
        sub = SubmitGate.for_subagent(log_path=Path(tempfile.mkdtemp()) / "s.jsonl",
                                      decoy_check=triage.is_decoy,
                                      reproducer=lambda cid, c: {"ok": True, "flag": c.value})
        with self.assertRaises(NotAuthorized):
            sub.submit_candidate("c1", _verified("acdc2026{win}"))

    def test_backward_compatible_without_gates(self):
        # no decoy_check / reproducer -> original behavior (submits a verified candidate)
        gate = SubmitGate.for_orchestrator(FakeClient("acdc2026{win}"),
                                           log_path=Path(tempfile.mkdtemp()) / "s.jsonl")
        self.assertEqual(gate.submit_candidate("c1", _verified("acdc2026{win}"))[0], "correct")


if __name__ == "__main__":
    unittest.main()
