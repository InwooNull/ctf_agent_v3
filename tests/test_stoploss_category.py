"""Category-aware StopLoss budgets (stoploss.caps_for + rotation wiring).

Motivated by the first real agent-method run: an analysis-heavy misc challenge needed
more than the flat 12-experiment cap. rev/misc now get more runway; crypto stays tight;
an explicit challenge_caps still overrides everything (backward compatible).
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import stoploss as SL
from orchestrator.rotation import RotationRunner


class TestCapsFor(unittest.TestCase):
    def test_analysis_categories_get_more_experiments(self):
        self.assertGreater(SL.caps_for("rev")["experiments"], SL.DEFAULT_CAPS["experiments"])
        self.assertGreater(SL.caps_for("misc")["experiments"], SL.DEFAULT_CAPS["experiments"])

    def test_crypto_stays_at_default(self):
        self.assertEqual(SL.caps_for("crypto")["experiments"], SL.DEFAULT_CAPS["experiments"])

    def test_unknown_or_none_falls_back_to_default(self):
        self.assertEqual(SL.caps_for(None), SL.DEFAULT_CAPS)
        self.assertEqual(SL.caps_for("nope"), SL.DEFAULT_CAPS)

    def test_case_insensitive_and_fresh_dict(self):
        self.assertEqual(SL.caps_for("REV"), SL.caps_for("rev"))
        a = SL.caps_for("rev"); a["experiments"] = 999
        self.assertNotEqual(SL.caps_for("rev")["experiments"], 999)  # not mutated


class TestRotationUsesCategoryCaps(unittest.TestCase):
    def _run_one_slice(self, items, challenge_caps=None):
        # a solver that makes no progress, so the slice records rounds against the cap
        solver = lambda cid, rnd, info: {"info_gain": 0}
        with tempfile.TemporaryDirectory() as d:
            r = RotationRunner(items, solver, d, challenge_caps=challenge_caps,
                               slice_rounds=1, no_progress_k=3)
            r._run_slice(items[0]["id"])
            return r.ch[items[0]["id"]]["stoploss"]["caps"]

    def test_rev_challenge_gets_category_cap_when_not_pinned(self):
        caps = self._run_one_slice([{"id": "c1", "category": "rev"}])
        self.assertEqual(caps["experiments"], SL.caps_for("rev")["experiments"])

    def test_explicit_caps_override_category(self):
        pinned = {"experiments": 5, "wall_s": 100.0, "tokens": 0}
        caps = self._run_one_slice([{"id": "c1", "category": "rev"}], challenge_caps=pinned)
        self.assertEqual(caps["experiments"], 5)

    def test_unknown_category_uses_default(self):
        caps = self._run_one_slice([{"id": "c1"}])  # no category
        self.assertEqual(caps["experiments"], SL.DEFAULT_CAPS["experiments"])


if __name__ == "__main__":
    unittest.main()
