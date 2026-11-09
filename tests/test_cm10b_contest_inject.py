"""CM10b — promoted contest experience is reinjected into the NEXT contest solve.

Locks the CM10b acceptance:
  1. run1 VERIFIED success -> promote -> inject -> the pattern text appears in a 2nd
     contest solve's skill_pack-injected prompt (via contest_log.skill_prompt);
  2. the injection source is the CONTEST store ONLY (a bench-store pattern never appears
     in skills/<pack>/experience_contest.md);
  3. the injection is logged to store/contest/injection_log.jsonl.

The injection file is written under the REAL skills/<pack>/ (that is the only place
skill_pack.load_pack globs); the test cleans it up in tearDown.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth import contest_growth as CG  # noqa: E402
from orchestrator import contest_log  # noqa: E402
from solver.contest_evidence import VERIFIED  # noqa: E402


class TestContestInjection(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "contest").mkdir(parents=True, exist_ok=True)
        # inject into the real web pack dir, but clean it up after.
        self.target = CG.SKILLS_DIR / "web" / CG.INJECTION_BASENAME
        self.assertFalse(self.target.exists(), "test expects no pre-existing contest injection")

    def tearDown(self):
        if self.target.exists():
            self.target.unlink()

    def test_promote_inject_reaches_next_prompt(self):
        # run 1: a VERIFIED web solve whose winning technique fingerprint is strings/xxd
        results = [{"cid": "run1-c", "category": "web", "verdict": VERIFIED,
                    "transcript_excerpt": "GET /backup via broker; strings then xxd printed flag",
                    "winning_exp": "e02", "subtype": "web-leak"}]
        promoted = CG.promote_contest(results, store_root=self.tmp)
        self.assertEqual(len(promoted), 1)

        out = CG.inject_contest(store_root=self.tmp)
        self.assertIn("web", out)
        self.assertTrue(self.target.exists())

        # run 2: a fresh web solve's prompt is built with the SAME injection path
        base = "Solve the web challenge run2-c at host:80"
        injected = contest_log.skill_prompt("web", base)
        self.assertIn(CG.INJECTION_BASENAME, injected)    # the contest file was concatenated
        self.assertIn("web-leak", injected)               # the promoted pattern's subtype
        self.assertIn("strings", injected)                # its technique fingerprint
        self.assertNotIn(base, injected[:0] or "")        # (sanity: injection appended, not replacing)
        self.assertTrue(injected.startswith(base))

    def test_injection_source_is_contest_only(self):
        # a bench-store record must NEVER appear in the contest injection file.
        bench_store = self.tmp / "experience_misc.jsonl"
        bench_store.write_text(
            '{"subtype":"BENCH_ONLY_SUBTYPE","category":"web","technique":["zsteg"],'
            '"recipe":"bench recipe","signals":"bench","no_flag":true}\n')
        # promote a contest pattern, then inject
        CG.promote_contest([{"cid": "c1", "category": "web", "verdict": VERIFIED,
                             "transcript_excerpt": "curl; base64 decode", "subtype": "web-contest"}],
                           store_root=self.tmp)
        CG.inject_contest(store_root=self.tmp)
        body = self.target.read_text()
        self.assertIn("web-contest", body)
        self.assertNotIn("BENCH_ONLY_SUBTYPE", body)      # bench never mixed in
        self.assertNotIn("bench recipe", body)

    def test_injection_logged(self):
        CG.promote_contest([{"cid": "c1", "category": "web", "verdict": VERIFIED,
                             "transcript_excerpt": "strings dump", "subtype": "web-x"}],
                           store_root=self.tmp)
        CG.inject_contest(store_root=self.tmp)
        log = self.tmp / "contest" / CG.INJECTION_LOG
        rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pack"], "web")
        self.assertEqual(rows[0]["source"], "contest")
        self.assertEqual(rows[0]["n_patterns"], 1)


if __name__ == "__main__":
    unittest.main()
