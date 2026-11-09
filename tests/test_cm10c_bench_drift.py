"""CM10c — blind bench-holdout drift gate on the cumulative contest injection.

Locks the CM10c acceptance:
  1. a deliberately BAD injection pattern -> the blind holdout regression gate detects a
     strict drop -> the injection is ROLLED BACK atomically and HASH-VERIFIED (the
     surface returns byte-identical to its pre-injection state);
  2. a GOOD injection (no holdout drop) is KEPT;
  3. the honest-scope provisional holdout flag (n≈2) rides along in the verdict.

The blind holdout is a deterministic fake keyed on the injection file content (cost 0),
standing in for the --network none / blind grader; it never reads a key.
"""
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth import contest_growth as CG  # noqa: E402
from growth.surface import Surface  # noqa: E402
from solver.contest_evidence import VERIFIED  # noqa: E402


class TestBenchDriftGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "contest").mkdir(parents=True, exist_ok=True)
        self.target = CG.SKILLS_DIR / "web" / CG.INJECTION_BASENAME
        self.assertFalse(self.target.exists(), "test expects a clean injection slot")

    def tearDown(self):
        if self.target.exists():
            self.target.unlink()

    def _holdout(self):
        """2-member blind holdout (n≈2). A POISON token in any injection file fails one
        member -> a strict drop; otherwise both pass."""
        def ev():
            poisoned = any("POISON" in t.read_text() for t in CG.injection_targets() if t.is_file())
            return {"h1": True, "h2": not poisoned}
        return ev

    def test_bad_injection_rolled_back_hash_verified(self):
        # promote a pattern whose rendered text carries the POISON marker (bad injection)
        CG.promote_contest([{"cid": "bad", "category": "web", "verdict": VERIFIED,
                             "transcript_excerpt": "strings dump", "subtype": "web-POISON"}],
                           store_root=self.tmp)
        pre = Surface(CG.injection_targets()).snapshot()   # pre-injection hashes
        res = CG.bench_regression_gate(self.tmp, holdout_eval=self._holdout())
        self.assertFalse(res["kept"])
        self.assertTrue(res["rolled_back"])
        self.assertTrue(res["hash_verified"])
        self.assertEqual(res["holdout_before"], 2)
        self.assertEqual(res["holdout_after"], 1)          # one member dropped
        self.assertLess(res["delta"], 0)
        # surface is byte-identical to pre-injection (file absent again)
        self.assertFalse(self.target.exists())
        post = Surface(CG.injection_targets()).snapshot()
        self.assertEqual(Surface.snapshot_hashes(pre), Surface.snapshot_hashes(post))

    def test_good_injection_kept(self):
        CG.promote_contest([{"cid": "good", "category": "web", "verdict": VERIFIED,
                             "transcript_excerpt": "curl; base64 decode", "subtype": "web-good"}],
                           store_root=self.tmp)
        res = CG.bench_regression_gate(self.tmp, holdout_eval=self._holdout())
        self.assertTrue(res["kept"])
        self.assertFalse(res["rolled_back"])
        self.assertEqual(res["delta"], 0)
        self.assertTrue(self.target.exists())              # kept on disk
        self.assertIn("web-good", self.target.read_text())
        self.assertIn("web", res["injection"])

    def test_provisional_scope_flag_present(self):
        CG.promote_contest([{"cid": "g", "category": "web", "verdict": VERIFIED,
                             "transcript_excerpt": "xxd", "subtype": "web-g"}], store_root=self.tmp)
        res = CG.bench_regression_gate(self.tmp, holdout_eval=self._holdout())
        self.assertEqual(res["holdout_scope"]["status"], "provisional")
        self.assertEqual(res["holdout_scope"]["n_effective"], 2)


if __name__ == "__main__":
    unittest.main()
