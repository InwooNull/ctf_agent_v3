"""CM10d — small end-to-end contest growth loop (deterministic, cost 0).

Chains CM10a->CM10b->CM10c across multiple dummy contest runs and locks the whole loop:

  run 1 : one VERIFIED solve + one CANDIDATE_UNVERIFIED guess + one tool_gap failure
          -> ONLY the verified solve is promoted (no false positive);
          -> the tool gap is routed to the human-gate needs.jsonl.
  gate  : a GOOD cumulative injection passes the blind holdout gate and is kept.
  run 2 : the promoted pattern is injected into the next solve's prompt AND concretely
          helps (a hint-gated solver verifies only because the technique is present).
  bad   : a POISON injection is caught by the bench gate and rolled back hash-identical.
  purity: the blind bench stores are byte-identical across the ENTIRE loop; the contest
          store is source="contest" only.
  drift : the 7 governance files stay byte-identical to governance_baseline.txt.
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
from growth.surface import Surface  # noqa: E402
from orchestrator import contest_log  # noqa: E402
from solver.contest_evidence import VERIFIED, CANDIDATE_UNVERIFIED  # noqa: E402


def _gov_hashes():
    out = {}
    for line in (PROJECT_ROOT / "growth" / "governance_baseline.txt").read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        want, rel = line.split()
        out[rel] = (want, hashlib.sha256((PROJECT_ROOT / rel).read_bytes()).hexdigest())
    return out


class TestCM10dE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "contest").mkdir(parents=True, exist_ok=True)
        self.target = CG.SKILLS_DIR / "web" / CG.INJECTION_BASENAME
        self.assertFalse(self.target.exists())
        # fake blind bench stores to prove non-contamination
        self.bench = {}
        for name in ("experience_misc.jsonl", "experience_ai.jsonl"):
            p = self.tmp / name
            p.write_text('{"schema":"x"}\n{"subtype":"bench","category":"web","technique":["zsteg"]}\n')
            self.bench[p] = hashlib.sha256(p.read_bytes()).hexdigest()

    def tearDown(self):
        if self.target.exists():
            self.target.unlink()

    def _clean_holdout(self):
        return lambda: {"h1": True, "h2": all(
            "POISON" not in t.read_text() for t in CG.injection_targets() if t.is_file())}

    def test_full_loop(self):
        gov_before = _gov_hashes()

        # ---- RUN 1: verified solve + guess + tool-gap failure -------------------
        run1 = [
            {"cid": "r1-solve", "category": "web", "verdict": VERIFIED,
             "transcript_excerpt": "GET /backup via broker; strings then base64 printed flag",
             "winning_exp": "e02", "subtype": "web-leak"},
            {"cid": "r1-guess", "category": "web", "verdict": CANDIDATE_UNVERIFIED,
             "transcript_excerpt": "theme-matched a flag, no evidence"},
            {"cid": "r1-toolgap", "category": "pwn", "verdict": CANDIDATE_UNVERIFIED,
             "signals": {"tool_missing": True}},
        ]
        promoted = CG.promote_contest(run1, store_root=self.tmp)
        self.assertEqual({r["cid"] for r in promoted}, {"r1-solve"})     # ONLY verified
        fails = [r for r in run1 if r["verdict"] != VERIFIED]
        diags, needs = CG.diagnose_contest(fails, self.tmp / "contest" / "needs.jsonl")
        by_cid = {d["cid"]: d["bucket"] for d in diags}
        self.assertEqual(by_cid["r1-toolgap"], "tool_gap")               # crisp non-AUTO
        self.assertEqual(by_cid["r1-guess"], "ambiguous")               # no signal -> fail-safe non-AUTO
        # both are non-AUTO -> both human-gated (never auto-applied); none is AUTO
        self.assertEqual({n["cid"] for n in needs}, {"r1-toolgap", "r1-guess"})
        self.assertTrue(all(n["gate"] == "human" for n in needs))

        # ---- GATE: good cumulative injection kept -------------------------------
        res = CG.bench_regression_gate(self.tmp, holdout_eval=self._clean_holdout())
        self.assertTrue(res["kept"] and not res["rolled_back"])
        self.assertTrue(self.target.exists())

        # ---- RUN 2: injection reaches the next prompt AND helps ------------------
        base = "Solve the web challenge r2-c at host:80"
        prompt = contest_log.skill_prompt("web", base)
        self.assertIn("web-leak", prompt)                                # pattern present

        # a hint-gated solver: verifies ONLY because the technique hint is in the prompt
        def solver(p):
            return VERIFIED if ("base64" in p and "web-leak" in p) else CANDIDATE_UNVERIFIED
        self.assertEqual(solver(prompt), VERIFIED)                       # reuse concretely helped
        self.assertEqual(solver(base), CANDIDATE_UNVERIFIED)             # without it, no solve

        # ---- BAD injection: caught + rolled back hash-identical -----------------
        pre = Surface(CG.injection_targets()).snapshot()
        CG.promote_contest([{"cid": "r3-bad", "category": "web", "verdict": VERIFIED,
                             "transcript_excerpt": "strings dump", "subtype": "web-POISON"}],
                           store_root=self.tmp)
        # holdout that fails when POISON is present
        bad_res = CG.bench_regression_gate(self.tmp, holdout_eval=self._clean_holdout())
        self.assertFalse(bad_res["kept"])
        self.assertTrue(bad_res["rolled_back"] and bad_res["hash_verified"])
        post = Surface(CG.injection_targets()).snapshot()
        self.assertEqual(Surface.snapshot_hashes(pre), Surface.snapshot_hashes(post))
        # the good pattern is restored exactly (POISON gone, web-leak back)
        self.assertTrue(self.target.exists())
        self.assertIn("web-leak", self.target.read_text())
        self.assertNotIn("POISON", self.target.read_text())

        # ---- PURITY: contest store source-only; bench byte-identical ------------
        for rec in CG.load_contest_experience(self.tmp):
            self.assertEqual(rec.get("source"), "contest")
        for p, h in self.bench.items():
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), h)

        # ---- DRIFT: governance 7/7 unchanged -----------------------------------
        gov_after = _gov_hashes()
        for rel, (want, now) in gov_after.items():
            self.assertEqual(want, now, f"governance file drifted: {rel}")
        self.assertEqual(gov_before, gov_after)
        self.assertEqual(len(gov_after), 7)


if __name__ == "__main__":
    unittest.main()
