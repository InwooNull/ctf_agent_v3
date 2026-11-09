"""CM10a — contest-run diagnosis + VERIFIED-only promotion (deterministic, cost 0).

Locks the three CM10a acceptance points:
  1. ONLY a VERIFIED contest solve is promoted; a CANDIDATE_UNVERIFIED guess (the contest
     FWS analogue) and a diagnosed failure are NEVER promoted (no false lessons).
  2. the blind bench stores store/experience_*.jsonl are byte-identical across a promote
     (physical separation / bench measurement purity).
  3. non-AUTO diagnoses (tool_gap / harness) go to a human-gate needs.jsonl, never a skill;
     promoted records carry NO flag.
"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth import contest_growth as CG  # noqa: E402
from solver.contest_evidence import VERIFIED, CANDIDATE_UNVERIFIED  # noqa: E402


def _ok(cid, category="web", excerpt="curl target; GET /flag printed the flag", winning_exp="e03", subtype=None):
    return {"cid": cid, "category": category, "verdict": VERIFIED,
            "transcript_excerpt": excerpt, "winning_exp": winning_exp,
            **({"subtype": subtype} if subtype else {})}


def _guess(cid, category="web"):
    # reported a flag but no evidence chain -> CANDIDATE_UNVERIFIED (contest FWS analogue)
    return {"cid": cid, "category": category, "verdict": CANDIDATE_UNVERIFIED,
            "transcript_excerpt": "theme-matched a plausible flag", "winning_exp": ""}


class TestContestPromotion(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "contest").mkdir(parents=True, exist_ok=True)

    def test_only_verified_promoted(self):
        results = [
            _ok("c_web", "web", excerpt="GET /admin via broker; strings printed flag"),
            _guess("c_guess", "web"),
        ]
        written = CG.promote_contest(results, store_root=self.tmp)
        cids = {r["cid"] for r in written}
        self.assertIn("c_web", cids)
        self.assertNotIn("c_guess", cids)
        self.assertEqual(len(written), 1)
        for r in written:
            self.assertEqual(r["source"], "contest")
            self.assertTrue(r["no_flag"])

    def test_unverified_only_batch_promotes_nothing(self):
        written = CG.promote_contest([_guess("g1"), _guess("g2")], store_root=self.tmp)
        self.assertEqual(written, [])
        self.assertEqual(CG.load_contest_experience(self.tmp), [])

    def test_no_flag_stored(self):
        CG.promote_contest([_ok("c1", excerpt="GET /f; FLAG{leak_me} in body")], store_root=self.tmp)
        blob = (self.tmp / "contest" / "experience_contest.jsonl").read_text()
        self.assertNotIn("FLAG{leak_me}", blob)
        self.assertNotIn("flag{", blob.lower())

    def test_dedup_by_technique(self):
        CG.promote_contest([_ok("c1", excerpt="strings dump", subtype="web")], store_root=self.tmp)
        again = CG.promote_contest([_ok("c2", excerpt="strings dump", subtype="web")], store_root=self.tmp)
        self.assertEqual(again, [])  # same (subtype, technique) -> deduped
        new = CG.promote_contest([_ok("c3", excerpt="xxd then base64", subtype="web")], store_root=self.tmp)
        self.assertEqual(len(new), 1)

    def test_bench_stores_untouched(self):
        # seed fake bench stores, record their hashes, promote, assert byte-identical.
        bench = []
        for name in ("experience_misc.jsonl", "experience_ai.jsonl"):
            p = self.tmp / name
            p.write_text('{"schema":"misc-solve-pattern/v1"}\n{"subtype":"bench","technique":["zsteg"]}\n')
            bench.append((p, hashlib.sha256(p.read_bytes()).hexdigest()))
        CG.promote_contest([_ok("c1", excerpt="binwalk carve")], store_root=self.tmp)
        for p, h in bench:
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), h,
                             f"bench store {p.name} was modified by a contest promote")

    def test_diagnose_routes_nonauto_to_needs(self):
        needs = self.tmp / "contest" / "needs.jsonl"
        fails = [
            {"cid": "f_tool", "category": "pwn", "verdict": CANDIDATE_UNVERIFIED,
             "signals": {"tool_missing": True}},
            {"cid": "f_harness", "category": "web", "verdict": CANDIDATE_UNVERIFIED,
             "signals": {"harness_error": True}},
        ]
        diags, written = CG.diagnose_contest(fails, needs, judge=None)
        buckets = {d["cid"]: d["bucket"] for d in diags}
        self.assertEqual(buckets["f_tool"], "tool_gap")
        self.assertEqual(buckets["f_harness"], "harness_bug")
        rows = [json.loads(l) for l in needs.read_text().splitlines() if l.strip()]
        self.assertEqual({r["cid"] for r in rows}, {"f_tool", "f_harness"})
        for r in rows:
            self.assertEqual(r["gate"], "human")
            self.assertEqual(r["source"], "contest")

    def test_diagnose_auto_not_in_needs(self):
        # an AUTO bucket (knowledge_gap via a confident judge) must NOT land in needs.jsonl
        needs = self.tmp / "contest" / "needs.jsonl"
        fails = [{"cid": "f_kg", "category": "web", "verdict": CANDIDATE_UNVERIFIED,
                  "signals": {"transcript_excerpt": "analysis stalled"}}]
        _, written = CG.diagnose_contest(fails, needs, judge=lambda s, e: ("knowledge_gap", 0.95))
        self.assertEqual(written, [])
        self.assertFalse(needs.exists() and needs.read_text().strip())


if __name__ == "__main__":
    unittest.main()
