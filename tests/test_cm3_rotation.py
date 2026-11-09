"""Phase CM3: rotation + per-challenge StopLoss + checkpoint/resume + events.jsonl.

Directly targets the WHITEHAT failure: no single challenge may monopolise the budget,
a budget-exhausted challenge is preserved and rotated (not discarded), and a token-cut
interruption loses NOTHING — every challenge's progress is checkpointed and resume
continues with zero re-run / duplicate.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import rotation as R                 # noqa: E402
from orchestrator import mode as mode_mod              # noqa: E402
from schemas.records import Candidate                  # noqa: E402


def _cand(v):
    return Candidate(value=v, confidence=0.9, evidence_refs=["e"], status="VERIFIED")


# A deterministic solver: behaviour is a pure function of (cid, round_idx). It records
# every (cid, round_idx) it is asked for, so tests can prove zero duplication on resume.
class Scripted:
    def __init__(self, calls):
        self.calls = calls          # shared list of (cid, round_idx)

    def __call__(self, cid, idx, info):
        self.calls.append((cid, idx))
        if cid == "easy":                       # solves immediately
            return {"info_gain": 1, "candidate": _cand("F{easy}")}
        if cid == "slow":                       # progresses, solves at round 3
            if idx < 3:
                return {"info_gain": 1}
            return {"info_gain": 1, "candidate": _cand("F{slow}")}
        if cid == "stall":                      # never gains -> stop-loss STOP
            return {"info_gain": 0}
        if cid == "greedy":                     # always "progresses", never solves
            return {"info_gain": 1}
        return {"info_gain": 0}


ITEMS = [
    {"id": "easy", "score": 100, "difficulty": "easy", "est_cost": 1.0},
    {"id": "slow", "score": 90, "difficulty": "med", "est_cost": 1.0},
    {"id": "stall", "score": 80, "difficulty": "med", "est_cost": 1.0},
    {"id": "greedy", "score": 70, "difficulty": "hard", "est_cost": 1.0},
]
CAPS = {"experiments": 4, "wall_s": 1200.0, "tokens": 0}
GLOBAL = {"experiments": 100, "time_s": 1e9}


def _events(store):
    return [json.loads(l) for l in (Path(store) / "events.jsonl").read_text().splitlines()]


class TestRotationAndMonopoly(unittest.TestCase):
    def test_full_run_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            calls = []
            run = R.RotationRunner(ITEMS, Scripted(calls), d, submit=lambda c, x: x is not None,
                                   global_caps=GLOBAL, challenge_caps=CAPS,
                                   slice_rounds=2, no_progress_k=3)
            summ = run.run()
        self.assertEqual(summ["status"]["easy"], R.SOLVED)
        self.assertEqual(summ["status"]["slow"], R.SOLVED)
        self.assertEqual(summ["status"]["stall"], R.STOPPED)
        self.assertEqual(summ["status"]["greedy"], R.STOPPED)
        self.assertEqual(set(summ["solved"]), {"easy", "slow"})

    def test_no_monopoly_greedy_bounded_others_attempted(self):
        with tempfile.TemporaryDirectory() as d:
            calls = []
            run = R.RotationRunner(ITEMS, Scripted(calls), d,
                                   global_caps=GLOBAL, challenge_caps=CAPS,
                                   slice_rounds=2, no_progress_k=3)
            summ = run.run()
        # greedy can never take more than its per-challenge hard cap (4), not the global 100
        self.assertEqual(summ["rounds"]["greedy"], 4)
        self.assertLess(summ["rounds"]["greedy"], GLOBAL["experiments"])
        # and every other challenge was still attempted (got >=1 round)
        for cid in ("easy", "slow", "stall"):
            self.assertGreaterEqual(summ["rounds"][cid], 1)

    def test_initial_triage_slice_for_all_first(self):
        with tempfile.TemporaryDirectory() as d:
            run = R.RotationRunner(ITEMS, Scripted([]), d,
                                   global_caps=GLOBAL, challenge_caps=CAPS,
                                   slice_rounds=2, no_progress_k=3)
            run.run()
            evs = _events(d)
        slice_starts = [e["cid"] for e in evs if e["event"] == "slice_start"]
        # the first 4 slice_starts are the 4 distinct challenges (round-robin triage)
        self.assertEqual(set(slice_starts[:4]), {"easy", "slow", "stall", "greedy"})

    def test_preserve_and_rotate_event(self):
        with tempfile.TemporaryDirectory() as d:
            run = R.RotationRunner(ITEMS, Scripted([]), d,
                                   global_caps=GLOBAL, challenge_caps=CAPS,
                                   slice_rounds=2, no_progress_k=3)
            run.run()
            evs = _events(d)
        # a budget-exhausted-but-unsolved challenge is preserved+rotated, never dropped
        rotates = [e for e in evs if e["event"] == "rotate" and e.get("preserved")]
        self.assertTrue(rotates, "expected at least one preserve+rotate event")

    def test_monopoly_invariant_rejects_bad_caps(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(R.MonopolyInvariantError):
                R.RotationRunner(ITEMS, Scripted([]), d,
                                 global_caps={"experiments": 100},
                                 challenge_caps={"experiments": 60})   # 60 > 0.5*100

    def test_single_challenge_skips_invariant(self):
        with tempfile.TemporaryDirectory() as d:
            # one challenge: the invariant does not apply (nothing to monopolise against)
            run = R.RotationRunner([ITEMS[0]], Scripted([]), d,
                                   global_caps={"experiments": 4},
                                   challenge_caps={"experiments": 4})
            self.assertIsNotNone(run)


class TestInterruptResume(unittest.TestCase):
    def test_resume_no_rerun_preserves_all(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            # 1) interrupt after 3 slices (simulates a token cut mid-set)
            run1 = R.RotationRunner(ITEMS, Scripted(calls), d, submit=lambda c, x: x is not None,
                                    global_caps=GLOBAL, challenge_caps=CAPS,
                                    slice_rounds=2, no_progress_k=3)
            summ1 = run1.run(max_slices=3)
            calls_after_interrupt = list(calls)

            # progress of MULTIPLE challenges must be preserved on disk, not just one
            st = json.loads((Path(d) / "state.json").read_text())["challenges"]
            touched = [c for c, s in st.items() if s["round"] > 0]
            self.assertGreaterEqual(len(touched), 2, "expected several challenges preserved")

            # 2) resume with a fresh runner on the SAME store
            run2 = R.RotationRunner(ITEMS, Scripted(calls), d, submit=lambda c, x: x is not None,
                                    global_caps=GLOBAL, challenge_caps=CAPS,
                                    slice_rounds=2, no_progress_k=3)
            # anything already terminal in run1 must be skipped on resume
            resumed_terminal = set(run2.summary()["by_status"].get(R.SOLVED, [])) | \
                set(run2.summary()["by_status"].get(R.STOPPED, []))
            summ2 = run2.run()

        # zero re-run / duplicate: no (cid, round_idx) solver call happened twice, ever
        self.assertEqual(len(calls), len(set(calls)), f"duplicate solver calls: {calls}")
        # solved challenges from run1 were not re-attempted in run2
        new_calls = calls[len(calls_after_interrupt):]
        for cid in summ1["solved"]:
            self.assertNotIn(cid, [c for c, _ in new_calls],
                             f"solved {cid} re-attempted after resume")
        # the resumed run reaches the same terminal outcome as a single uninterrupted run
        self.assertEqual(set(summ2["solved"]), {"easy", "slow"})
        self.assertEqual(summ2["status"]["stall"], R.STOPPED)
        self.assertEqual(summ2["status"]["greedy"], R.STOPPED)

    def test_resume_emits_resume_events(self):
        with tempfile.TemporaryDirectory() as d:
            R.RotationRunner(ITEMS, Scripted([]), d, global_caps=GLOBAL,
                             challenge_caps=CAPS, slice_rounds=2, no_progress_k=3).run(max_slices=2)
            R.RotationRunner(ITEMS, Scripted([]), d, global_caps=GLOBAL,
                             challenge_caps=CAPS, slice_rounds=2, no_progress_k=3).run()
            evs = _events(d)
        kinds = {e["event"] for e in evs}
        self.assertTrue({"resume_skip", "resume_continue"} & kinds,
                        "expected resume_skip or resume_continue events")


class TestEventsLog(unittest.TestCase):
    def test_events_jsonl_written_and_shaped(self):
        with tempfile.TemporaryDirectory() as d:
            R.RotationRunner(ITEMS, Scripted([]), d, global_caps=GLOBAL,
                             challenge_caps=CAPS, slice_rounds=2, no_progress_k=3).run()
            evs = _events(d)
        self.assertTrue(evs)
        for e in evs:
            self.assertIn("ts", e)
            self.assertIn("cid", e)
            self.assertIn("event", e)
        kinds = {e["event"] for e in evs}
        self.assertTrue({"slice_start", "round", "solved", "stopped"} <= kinds)


class TestBenchAndGovernanceUntouched(unittest.TestCase):
    def test_mode_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            run = R.RotationRunner(ITEMS, Scripted([]), d, global_caps=GLOBAL,
                                   challenge_caps=CAPS, slice_rounds=2, no_progress_k=3)
            self.assertEqual(run.mode, mode_mod.CONTEST)
            summ = run.run()
            self.assertEqual(summ["mode"], mode_mod.CONTEST)
            st = json.loads((Path(d) / "state.json").read_text())
            self.assertEqual(st["mode"], mode_mod.CONTEST)

    def test_seven_files_hash_invariant(self):
        baseline = (PROJECT_ROOT / "growth" / "governance_baseline.txt").read_text().splitlines()
        for line in baseline:
            line = line.strip()
            if not line:
                continue
            want, rel = line.split()[0], line.split()[-1]
            got = hashlib.sha256((PROJECT_ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"governance file changed: {rel}")


if __name__ == "__main__":
    unittest.main()
