"""Phase 44c: Improver + Regressor — sequential one-at-a-time gating, atomic
hash-verified rollback, the dual adoption condition, and variance-conservative ties.

Vault-free / token-free: the surface is a set of temp files; dev_eval / holdout_eval are
deterministic stubs driven by the current file CONTENT (so a change's effect is visible
and reproducible, exactly as a --network none fixed-input run would be).
"""
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth.surface import Surface, sha256_bytes, RollbackError  # noqa: E402
from growth.regress import Regressor  # noqa: E402
from growth.improver import Improver, Improvement  # noqa: E402


# --- a content-driven world: a managed file holds "tokens"; dev/holdout "solve" when a
#     cid's required token is present. This makes a change's effect deterministic. --------
def world(tmp):
    f = Path(tmp) / "skills.md"
    f.write_text("BASE\n")
    return f


def set_token(f, tok):
    def _mut(surface):
        f.write_text(f.read_text() + tok + "\n")
    return _mut


def break_file(f):
    def _mut(surface):
        f.write_text("CORRUPT\n")       # a bad change that helps nothing
    return _mut


def dev_eval_for(f, needs):
    """needs: {cid: token}. A dev cid solves iff its token is in the file now."""
    def _ev(cids):
        txt = f.read_text()
        return {c: (needs[c] in txt) for c in cids}
    return _ev


def holdout_eval_for(f, members):
    """members: {cid: token}. Holdout score = how many members' tokens are present AND the
    file is not corrupt (a corrupt cheatsheet regresses holdout)."""
    def _ev():
        txt = f.read_text()
        ok = "CORRUPT" not in txt
        return {c: (ok and (tok in txt or tok == "BASE")) for c, tok in members.items()}
    return _ev


class TestAtomicRollbackHash(unittest.TestCase):
    """REQUIRED: a bad change, once rolled back, leaves the surface byte-identical."""

    def test_rollback_restores_exact_bytes(self):
        with tempfile.TemporaryDirectory() as t:
            f = world(t)
            surf = Surface([f])
            before = surf.hashes()
            snap = surf.snapshot()
            # apply a destructive change
            f.write_text("TOTALLY DIFFERENT CONTENT")
            self.assertNotEqual(surf.hashes(), before)
            # atomic rollback + verify
            self.assertTrue(surf.restore(snap))
            self.assertEqual(surf.hashes(), before)
            self.assertEqual(sha256_bytes(f.read_bytes()), before[str(f)])

    def test_rollback_recreates_absent_file(self):
        with tempfile.TemporaryDirectory() as t:
            missing = Path(t) / "exp_store.json"
            surf = Surface([missing])
            snap = surf.snapshot()                 # file absent at snapshot
            missing.write_text("created by a change")
            surf.restore(snap)
            self.assertFalse(missing.exists())     # restored to absent, no residue


class TestDualCondition(unittest.TestCase):
    """REQUIRED x2: flip-less holdout-tie -> rollback; flip + no-drop -> adopt."""

    def test_flipless_holdout_tie_is_rolled_back(self):
        with tempfile.TemporaryDirectory() as t:
            f = world(t)
            surf = Surface([f])
            # dev target 'd1' needs token 'FIX' — but this improvement adds 'NOISE', so the
            # target does NOT flip; holdout is a tie (file still fine). Must roll back.
            reg = Regressor(dev_eval_for(f, {"d1": "FIX"}),
                            holdout_eval_for(f, {"h1": "BASE", "h2": "BASE"}))
            imp = Improvement("i-noise", "approach", ["d1"], set_token(f, "NOISE"))
            applied, rolled_back, delta = Improver(surf, reg).apply([imp])
            self.assertEqual(applied, [])
            self.assertEqual(len(rolled_back), 1)
            self.assertFalse(rolled_back[0]["verdict"]["flip"])
            self.assertTrue(rolled_back[0]["verdict"]["no_drop"])   # holdout tie, yet NOT adopted
            self.assertTrue(rolled_back[0]["rollback_verified"])
            self.assertEqual(f.read_text(), "BASE\n")              # reverted

    def test_flip_and_no_drop_is_adopted(self):
        with tempfile.TemporaryDirectory() as t:
            f = world(t)
            surf = Surface([f])
            reg = Regressor(dev_eval_for(f, {"d1": "FIX"}),
                            holdout_eval_for(f, {"h1": "BASE"}))
            imp = Improvement("i-fix", "knowledge_gap", ["d1"], set_token(f, "FIX"))
            applied, rolled_back, delta = Improver(surf, reg).apply([imp])
            self.assertEqual(len(applied), 1)
            self.assertTrue(applied[0]["verdict"]["flip"])
            self.assertTrue(applied[0]["verdict"]["no_drop"])
            self.assertIn("FIX", f.read_text())                    # kept


class TestHoldoutDropRolledBack(unittest.TestCase):
    def test_flip_but_holdout_drop_is_rolled_back(self):
        """A change can fix its dev target yet REGRESS holdout -> must roll back (b fails)."""
        with tempfile.TemporaryDirectory() as t:
            f = world(t)
            surf = Surface([f])
            # mutate writes FIX (flips d1) but we simulate a holdout regressor by making the
            # mutation ALSO corrupt: use a combined mutate.
            def mut(surface):
                f.write_text("CORRUPT\nFIX\n")     # d1 sees FIX (flip) but holdout sees CORRUPT
            reg = Regressor(dev_eval_for(f, {"d1": "FIX"}),
                            holdout_eval_for(f, {"h1": "BASE", "h2": "BASE"}))
            imp = Improvement("i-bad", "approach", ["d1"], mut)
            applied, rolled_back, delta = Improver(surf, reg).apply([imp])
            self.assertEqual(applied, [])
            self.assertTrue(rolled_back[0]["verdict"]["flip"])
            self.assertFalse(rolled_back[0]["verdict"]["no_drop"])
            self.assertEqual(f.read_text(), "BASE\n")


class TestSequentialAttribution(unittest.TestCase):
    """REQUIRED: two changes, only one regresses -> only that one rolls back; the other
    is adopted. Proves per-change gating + blast-radius containment."""

    def test_only_the_regressing_change_rolls_back(self):
        with tempfile.TemporaryDirectory() as t:
            f = world(t)
            surf = Surface([f])
            reg = Regressor(dev_eval_for(f, {"d1": "FIX1", "d2": "FIX2"}),
                            holdout_eval_for(f, {"h1": "BASE", "h2": "BASE"}))
            good = Improvement("good", "knowledge_gap", ["d1"], set_token(f, "FIX1"))
            # 'bad' flips its own dev target (writes FIX2) but corrupts the file -> holdout drop
            def bad_mut(surface):
                f.write_text(f.read_text() + "FIX2\nCORRUPT\n")
            bad = Improvement("bad", "approach", ["d2"], bad_mut)
            applied, rolled_back, delta = Improver(surf, reg).apply([good, bad])
            self.assertEqual([a["id"] for a in applied], ["good"])
            self.assertEqual([r["id"] for r in rolled_back], ["bad"])
            # the good change survives; the bad one left NO residue
            self.assertIn("FIX1", f.read_text())
            self.assertNotIn("CORRUPT", f.read_text())
            self.assertTrue(rolled_back[0]["rollback_verified"])


class TestBudgetCap(unittest.TestCase):
    def test_over_cap_budget_change_refused(self):
        with tempfile.TemporaryDirectory() as t:
            f = world(t)
            reg = Regressor(dev_eval_for(f, {"d1": "X"}), holdout_eval_for(f, {"h1": "BASE"}))
            over = Improvement("b", "budget", ["d1"], set_token(f, "X"), within_cap=False)
            applied, rolled_back, delta = Improver(Surface([f]), reg).apply([over])
            self.assertEqual(applied, [])
            self.assertEqual(rolled_back[0]["reason"].split(";")[0], "budget proposal exceeds cap")
            self.assertEqual(f.read_text(), "BASE\n")          # never applied


class TestBuildExcludesNonAutoAndFws(unittest.TestCase):
    def test_build_skips_nonauto_and_uses_only_promotable_successes(self):
        from growth.loop import RunOutcome
        with tempfile.TemporaryDirectory() as t:
            f = world(t)
            seen = []
            def drafter(d, runs, successes):
                seen.append((d["bucket"], [s.cid for s in successes]))
                return None            # we only check WHAT build passes through
            imp = Improver(Surface([f]), Regressor(lambda c: {}, lambda: {}), drafter=drafter)
            diags = [{"bucket": "knowledge_gap"}, {"bucket": "tool_gap"}, {"bucket": "harness_bug"}]
            runs = [RunOutcome("ok", "SOLVED", True),
                    RunOutcome("fws", "FLAG_WITHOUT_SOLUTION", False)]
            imp.build(diags, runs)
            self.assertEqual([s[0] for s in seen], ["knowledge_gap"])    # non-AUTO skipped
            self.assertEqual(seen[0][1], ["ok"])                          # FWS excluded from successes


if __name__ == "__main__":
    unittest.main()
