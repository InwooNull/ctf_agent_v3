"""Phase 44d: small autonomous-cycle validation (deterministic fakes, cost 0).

Locks the four 44d requirements:
  1. multi-cycle chaining + power-loss recovery DURING the improve step (resume from the
     exact point, no batch re-run, no double-apply of an already-decided change);
  2. convergence actually fires (N cycles with net 0 adoption -> stop_reason);
  3. the HUMAN-GATE / SKIP boundary persists across cycles (accumulate in requests.md,
     0 auto-applied; cyber_blocked deduped to one line per cid across cycles);
  4. final governance/isolation drift proof (7 files match governance_baseline.txt).

This is skeleton + safety validation only. The FIRST real autonomous growth run against
the live blind runner is a SEPARATE later milestone, not 44d.
"""
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth.loop import GrowthLoop, BatchResult, RunOutcome  # noqa: E402
from growth.diagnoser import Diagnoser  # noqa: E402
from growth.improver import Improver, Improvement  # noqa: E402
from growth.regress import Regressor  # noqa: E402
from growth.surface import Surface, sha256_bytes  # noqa: E402

KG_JUDGE = lambda s, e: ("knowledge_gap", 0.9)   # residual analysis-fails -> confident AUTO


def fail_runs(cids, **sig):
    return [RunOutcome(c, "GIVE_UP", False, signals=dict(sig)) for c in cids]


class TestMidImproveCrashRecovery(unittest.TestCase):
    def test_resume_midimprove_no_rerun_no_double_apply(self):
        with tempfile.TemporaryDirectory() as t:
            run_dir = Path(t) / "run"
            cheats = Path(t) / "c.md"
            cheats.write_text("BASE\n")
            surface = Surface([cheats])
            flags = {"crash": True}

            def drafter(d, runs, succ):
                cid = d["cid"]
                if cid == "d1":
                    def m(_s): cheats.write_text(cheats.read_text() + "FIX1\n")
                    return Improvement("imp1", "knowledge_gap", ["d1"], m)
                if cid == "d2":
                    def m(_s):
                        if flags["crash"]:        # power loss mid-apply of imp2, once
                            flags["crash"] = False
                            raise RuntimeError("simulated power loss")
                        cheats.write_text(cheats.read_text() + "FIX2\n")
                    return Improvement("imp2", "knowledge_gap", ["d2"], m)
                return None

            needs = {"d1": "FIX1", "d2": "FIX2"}
            reg = Regressor(lambda cs: {c: needs[c] in cheats.read_text() for c in cs},
                            lambda: {"h1": "CORRUPT" not in cheats.read_text()})
            improver = Improver(surface, reg, drafter=drafter)
            dx = Diagnoser(judge=KG_JUDGE)
            calls = []

            def rb(dev):
                calls.append(1)
                return BatchResult(runs=fail_runs(dev, give_up_kind="analysis"))

            # cycle 1 crashes during imp2's mutate (imp1 already adopted + checkpointed)
            loop1 = GrowthLoop(run_dir, run_batch=rb, diagnoser=dx, improver=improver)
            with self.assertRaises(RuntimeError):
                loop1.cycle(["d1", "d2"])
            self.assertEqual(len(calls), 1)

            # a fresh loop (fresh in-memory process) resumes from the checkpoint
            loop2 = GrowthLoop(run_dir, run_batch=rb, diagnoser=dx, improver=improver)
            rep = loop2.cycle(["d1", "d2"])

            self.assertEqual(len(calls), 1)                        # batch NOT re-run
            self.assertEqual(cheats.read_text().count("FIX1"), 1)  # imp1 NOT re-applied
            self.assertIn("FIX2", cheats.read_text())              # imp2 finished on resume
            self.assertEqual(sorted(a["id"] for a in rep.improvements_applied), ["imp1", "imp2"])
            self.assertIsNone(loop2.state.resume_cycle_id())       # cycle completed


class TestConvergenceFires(unittest.TestCase):
    def test_net_zero_adoptions_converges(self):
        with tempfile.TemporaryDirectory() as t:
            cheats = Path(t) / "c.md"; cheats.write_text("BASE\n")
            surface = Surface([cheats])

            def drafter(d, runs, succ):
                # an improvement that never flips its dev target -> always rolled back
                def m(_s): cheats.write_text(cheats.read_text() + "NOISE\n")
                return Improvement(f"noop-{d['cid']}", "approach", [d["cid"]], m)

            reg = Regressor(lambda cs: {c: False for c in cs},      # target never flips
                            lambda: {"h1": True})
            loop = GrowthLoop(Path(t) / "run",
                              run_batch=lambda dev: BatchResult(runs=fail_runs(dev, give_up_kind="analysis")),
                              diagnoser=Diagnoser(judge=KG_JUDGE),
                              improver=Improver(surface, reg, drafter=drafter),
                              no_progress_k=2, max_cycles=10)
            reports = loop.run(["d1"])
            self.assertEqual(reports[-1].stop_reason, "converged_no_progress")
            self.assertTrue(all(len(r.improvements_applied) == 0 for r in reports))
            self.assertEqual(len(reports), 2)
            self.assertEqual(cheats.read_text(), "BASE\n")         # every change reverted


class TestHumanGatePersistsAcrossCycles(unittest.TestCase):
    def test_nonauto_accumulates_zero_autoapplied_cyber_dedup(self):
        with tempfile.TemporaryDirectory() as t:
            cheats = Path(t) / "c.md"; cheats.write_text("BASE\n")
            req = Path(t) / "requests.md"
            dev = ["d_tool", "d_harn", "d_hg", "d_cy"]

            def rb(_dev):
                return BatchResult(runs=[
                    RunOutcome("d_tool", "GIVE_UP", False, signals={"tool_missing": True}),
                    RunOutcome("d_harn", "GIVE_UP", False, signals={"harness_error": True}),
                    RunOutcome("d_hg", "GIVE_UP", False, signals={"human_grade_hint": True}),
                    RunOutcome("d_cy", "GIVE_UP", False, signals={"cyber_blocked": True}),
                ])

            reg = Regressor(lambda cs: {}, lambda: {"h1": True})
            loop = GrowthLoop(Path(t) / "run", run_batch=rb, diagnoser=Diagnoser(judge=None),
                              improver=Improver(Surface([cheats]), reg, drafter=lambda *a: None),
                              max_cycles=2, no_progress_k=9, requests_path=req)
            reports = loop.run(dev)

            self.assertEqual(len(reports), 2)
            total_applied = sum(len(r.improvements_applied) for r in reports)
            self.assertEqual(total_applied, 0)                     # ZERO auto-applied
            txt = req.read_text()
            self.assertIn("tool_gap :: d_tool", txt)
            self.assertIn("harness_bug :: d_harn", txt)
            self.assertIn("human_grade :: d_hg", txt)
            # cyber_blocked logged ONCE per cid even across the two cycles
            self.assertEqual(txt.count("cyber_blocked :: d_cy"), 1)
            self.assertEqual(cheats.read_text(), "BASE\n")         # surface untouched


class TestGovernanceDriftProof(unittest.TestCase):
    """REQUIRED 4: the 7 governance/isolation files still match governance_baseline.txt."""

    def test_governance_files_match_baseline(self):
        base = PROJECT_ROOT / "growth" / "governance_baseline.txt"
        self.assertTrue(base.is_file(), "governance_baseline.txt missing")
        for line in base.read_text().splitlines():
            if not line.strip():
                continue
            want_hash, rel = line.split()
            cur = sha256_bytes((PROJECT_ROOT / rel).read_bytes())
            self.assertEqual(cur, want_hash, f"governance drift in {rel}")


if __name__ == "__main__":
    unittest.main()
