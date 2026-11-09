"""Phase 44a: GrowthLoop skeleton + checkpoint/resume.

Vault-free and token-free: run_batch is a deterministic fake (the loop never runs a real
solver — in production run_batch wraps an existing blind runner). Locks: a cycle with no
diagnoser/improver is a clean no-op that still produces a CycleReport and checkpoints;
and a cycle interrupted after the RUN step resumes WITHOUT re-running the batch.
"""
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth.loop import GrowthLoop, BatchResult, RunOutcome  # noqa: E402
from growth.state import GrowthState  # noqa: E402

DEV = ["d_a", "d_b", "d_c", "d_d"]   # a 4-problem dev small-batch


def fake_run_batch(solved_set, counter=None):
    """Return a run_batch callable; `counter` (list) counts invocations."""
    def _rb(dev_batch):
        if counter is not None:
            counter.append(1)
        runs = [RunOutcome(cid=c, outcome="SOLVED" if c in solved_set else "GIVE_UP",
                           solved=(c in solved_set), category="crypto",
                           difficulty="med", run_dir=f"/tmp/{c}", trace_ref=f"/tmp/{c}/t.jsonl")
                for c in dev_batch]
        report = {"outcomes": {"SOLVED": len(solved_set & set(dev_batch))}}
        return BatchResult(runs=runs, report=report)
    return _rb


class TestCycleSkeleton(unittest.TestCase):
    def test_empty_cycle_runs_and_reports(self):
        with tempfile.TemporaryDirectory() as t:
            loop = GrowthLoop(t, run_batch=fake_run_batch({"d_a", "d_c"}))
            rep = loop.cycle(DEV)
            self.assertEqual(rep.cycle_id, "c1")
            self.assertEqual(sorted(rep.solved), ["d_a", "d_c"])
            self.assertEqual(sorted(rep.failed), ["d_b", "d_d"])
            # empty diagnose/improve/regress
            self.assertEqual(rep.diagnoses, [])
            self.assertEqual(rep.improvements_applied, [])
            self.assertEqual(rep.improvements_rolled_back, [])
            self.assertEqual(rep.regression_delta, 0.0)
            self.assertIsNone(rep.stop_reason)

    def test_report_persisted_and_next_cycle_increments(self):
        with tempfile.TemporaryDirectory() as t:
            loop = GrowthLoop(t, run_batch=fake_run_batch({"d_a"}))
            loop.cycle(DEV)
            loop.cycle(DEV)
            # a fresh loop from the same store sees both completed cycles
            loop2 = GrowthLoop(t, run_batch=fake_run_batch({"d_a"}))
            self.assertEqual(loop2.state.completed_cycle_ids(), ["c1", "c2"])
            rep3 = loop2.cycle(DEV)
            self.assertEqual(rep3.cycle_id, "c3")

    def test_schema_fields_present(self):
        with tempfile.TemporaryDirectory() as t:
            loop = GrowthLoop(t, run_batch=fake_run_batch(set()))
            d = loop.cycle(DEV).to_dict()
            for k in ("cycle_id", "solved", "failed", "diagnoses", "improvements_applied",
                      "improvements_rolled_back", "regression_delta", "stop_reason"):
                self.assertIn(k, d)


class TestCheckpointResume(unittest.TestCase):
    def test_resume_after_run_step_does_not_rerun_batch(self):
        """Simulate a crash right after the RUN step: a new loop must resume from the
        checkpoint and finish the cycle WITHOUT calling run_batch again."""
        with tempfile.TemporaryDirectory() as t:
            # 1) first loop records only the RUN step, then "crashes" (we stop driving it)
            st = GrowthState(t)
            st.begin_cycle("c1")
            st.record_step("run", {
                "solved": ["d_a"], "failed": ["d_b"],
                "failed_runs": [RunOutcome("d_b", "GIVE_UP", False).__dict__]})

            # 2) a new loop whose run_batch would RAISE if called — proving it resumed
            def exploding_rb(_):
                raise AssertionError("run_batch must NOT be called on resume after RUN")
            loop = GrowthLoop(t, run_batch=exploding_rb)
            rep = loop.cycle(DEV)              # cycle_id defaults to the in-progress "c1"
            self.assertEqual(rep.cycle_id, "c1")
            self.assertEqual(rep.solved, ["d_a"])
            self.assertEqual(rep.failed, ["d_b"])
            self.assertIsNone(loop.state.resume_cycle_id())   # cleared after completion

    def test_batch_runs_exactly_once_per_cycle(self):
        with tempfile.TemporaryDirectory() as t:
            counter = []
            loop = GrowthLoop(t, run_batch=fake_run_batch({"d_a"}, counter=counter))
            loop.cycle(DEV)
            self.assertEqual(len(counter), 1)


class TestRunUntilStop(unittest.TestCase):
    def test_max_cycles_stop(self):
        with tempfile.TemporaryDirectory() as t:
            loop = GrowthLoop(t, run_batch=fake_run_batch({"d_a"}), max_cycles=2)
            reports = loop.run(DEV)
            self.assertEqual(len(reports), 2)
            self.assertEqual(loop.state.completed_cycle_ids(), ["c1", "c2"])
            self.assertEqual(reports[-1].stop_reason, "max_cycles")

    def test_converged_no_progress_stop(self):
        """No new solves and no improvements for no_progress_k cycles -> converge."""
        with tempfile.TemporaryDirectory() as t:
            loop = GrowthLoop(t, run_batch=fake_run_batch(set()), no_progress_k=2, max_cycles=10)
            reports = loop.run(DEV)
            self.assertEqual(reports[-1].stop_reason, "converged_no_progress")
            self.assertLessEqual(len(reports), 2)


if __name__ == "__main__":
    unittest.main()
