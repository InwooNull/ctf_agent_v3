"""Phase CM4: evidence capture / false-positive quarantine / writeup log / skill_pack
injection / candidate display with NO auto-submit / contest-vs-bench experience split.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from solver import contest_evidence as ce           # noqa: E402
from orchestrator import contest_log as cl           # noqa: E402
from orchestrator import rotation as R               # noqa: E402
from orchestrator import mode as mode_mod            # noqa: E402
from orchestrator import skill_pack                  # noqa: E402
from schemas.records import Candidate                 # noqa: E402

FMT = "flag{...}"
REAL = "flag{pr0v3n_fr0m_target}"
GUESS = "flag{i_am_guessing}"


def _cand(v, refs=None):
    return Candidate(value=v, confidence=0.5, evidence_refs=refs or [], status="VERIFIED")


class TestFormatAndClassify(unittest.TestCase):
    def test_matches_format(self):
        self.assertTrue(ce.matches_format("flag{abc}", FMT))
        self.assertFalse(ce.matches_format("wrong{abc}", FMT))
        self.assertFalse(ce.matches_format("flag-no-brace", FMT))
        self.assertFalse(ce.matches_format("", FMT))

    def test_classify_grounded_is_verified(self):
        res = ce.classify(REAL, FMT, ["server said: " + REAL + " bye"])
        self.assertEqual(res["verdict"], ce.VERIFIED)

    def test_classify_guess_without_evidence_is_unverified(self):
        res = ce.classify(GUESS, FMT, ["server said: nope"])
        self.assertEqual(res["verdict"], ce.CANDIDATE_UNVERIFIED)
        self.assertEqual(res["reason"], "no_evidence")

    def test_classify_bad_format_is_unverified(self):
        res = ce.classify("not-a-flag", FMT, ["not-a-flag appears here"])
        self.assertEqual(res["verdict"], ce.CANDIDATE_UNVERIFIED)
        self.assertEqual(res["reason"], "bad_format")


class TestContestVerifier(unittest.TestCase):
    def test_flag_from_target_output_is_solved_with_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            cv = ce.ContestVerifier(d, flag_format=FMT)
            ref = cv.capture(ce.SRC_TARGET, f"HTTP/1.1 200 OK\n\n{REAL}\n", label="GET /flag")
            res = cv.assess(REAL)
            self.assertEqual(res["verdict"], ce.VERIFIED)
            self.assertEqual(res["evidence_refs"], [ref])
            self.assertGreater(res["confidence"], 0.9)
            self.assertTrue(cv.is_solved("c1", _cand(REAL)))
            # evidence persisted on disk (attributable)
            self.assertTrue((Path(d) / "evidence" / f"{ref}.txt").exists())
            idx = [json.loads(l) for l in (Path(d) / "evidence" / "evidence.jsonl").read_text().splitlines()]
            self.assertEqual(idx[0]["source"], ce.SRC_TARGET)

    def test_guess_without_evidence_is_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            cv = ce.ContestVerifier(d, flag_format=FMT)
            cv.capture(ce.SRC_TARGET, "nothing useful here", label="probe")
            res = cv.assess(GUESS)
            self.assertEqual(res["verdict"], ce.CANDIDATE_UNVERIFIED)
            self.assertFalse(cv.is_solved("c1", _cand(GUESS)))

    def test_capture_rejects_bad_source(self):
        with tempfile.TemporaryDirectory() as d:
            cv = ce.ContestVerifier(d, flag_format=FMT)
            with self.assertRaises(ValueError):
                cv.capture("fabricated", "x")


class TestContestVerifierDrivesRotation(unittest.TestCase):
    """CM3 runner + CM4 verifier: only an evidence-grounded flag ends as SOLVED."""
    def test_grounded_solves_guess_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = Path(d) / "run"
            cv = ce.ContestVerifier(run_dir, flag_format=FMT)
            cv.capture(ce.SRC_TARGET, f"...{REAL}...")      # evidence for the real flag only

            def solver(cid, idx, info):
                flag = REAL if cid == "good" else GUESS
                return {"info_gain": 1, "candidate": _cand(flag)}

            items = [{"id": "good", "score": 100, "difficulty": "easy", "est_cost": 1},
                     {"id": "bad", "score": 90, "difficulty": "easy", "est_cost": 1}]
            run = R.RotationRunner(items, solver, Path(d) / "store", submit=cv.is_solved,
                                   global_caps={"experiments": 50},
                                   challenge_caps={"experiments": 4}, slice_rounds=2)
            summ = run.run()
        self.assertEqual(summ["status"]["good"], R.SOLVED)      # grounded -> solved
        self.assertEqual(summ["status"]["bad"], R.STOPPED)      # guess never verified


class TestWriteupLog(unittest.TestCase):
    def test_records_model_prompt_output(self):
        with tempfile.TemporaryDirectory() as d:
            w = cl.WriteupLog(d)
            w.record("c1", model="claude-opus-4-8", prompt="pwn the service",
                     output="leaked libc, got shell, flag=" + REAL, step="exploit")
            w.record("c1", model="claude-opus-4-8", prompt="verify",
                     output="server returned " + REAL, step="verify")
            e = w.entries()
        self.assertEqual(len(e), 2)
        self.assertEqual(e[0]["model"], "claude-opus-4-8")
        self.assertEqual(e[0]["step"], "exploit")
        self.assertIn("prompt", e[0])
        self.assertIn(REAL, e[1]["output"])          # contest: flag value allowed


class TestCandidateBoardNoAutoSubmit(unittest.TestCase):
    def test_present_writes_manual_and_never_submits(self):
        # guard: if any code path tried to submit to a CTFd, this would record a call
        import connector.ctfd_client as cc
        calls = []
        orig = cc.CTFdClient.submit_flag
        cc.CTFdClient.submit_flag = lambda self, *a, **k: calls.append(a) or ("correct", "")
        try:
            with tempfile.TemporaryDirectory() as d:
                board = cl.CandidateBoard(d)
                line = board.present("c1", REAL, verdict="VERIFIED", confidence=0.99,
                                     evidence_refs=["ev0000_target"])
                board.present("c2", GUESS, verdict="CANDIDATE_UNVERIFIED", confidence=0.2)
                recs = board.all()
                verified_cids = [r["cid"] for r in board.verified()]
        finally:
            cc.CTFdClient.submit_flag = orig
        self.assertEqual(calls, [])                           # ZERO auto-submits
        self.assertIn("submit manually", line)
        self.assertTrue(all(r["submitted"] is False for r in recs))
        self.assertTrue(all(r["action"] == "manual_submit_by_user" for r in recs))
        self.assertEqual(verified_cids, ["c1"])


class TestSkillPackInjection(unittest.TestCase):
    def test_contest_prompt_gets_pack(self):
        base = "Solve the web challenge at http://target."
        injected = cl.skill_prompt("web", base)
        self.assertNotEqual(injected, base)
        self.assertGreater(len(injected), len(base))
        self.assertIn(base, injected)

    def test_no_pack_category_passthrough(self):
        base = "x"
        self.assertEqual(cl.skill_prompt("nonexistent_cat", base), base)


class TestExperienceSeparation(unittest.TestCase):
    def test_contest_experience_tagged_and_isolated(self):
        with tempfile.TemporaryDirectory() as root:
            exp = cl.ContestExperience(store_root=root)
            exp.add({"technique": "ssrf->metadata", "recipe": "step1; step2"})
            recs = exp.all()
            self.assertEqual(recs[0]["source"], "contest")
            # written under store/contest/, NOT into any blind bench store file
            self.assertTrue((Path(root) / "contest" / "experience_contest.jsonl").exists())
            self.assertFalse((Path(root) / "experience_misc.jsonl").exists())
            self.assertFalse((Path(root) / "experience_ai.jsonl").exists())
            # nothing bench-named anywhere under the temp root
            self.assertEqual(list(Path(root).glob("experience_*.jsonl")), [])

    def test_real_bench_stores_untouched(self):
        # adding contest experience to a temp root must not touch the project's bench stores
        bench = PROJECT_ROOT / "store" / "experience_misc.jsonl"
        before = bench.read_bytes() if bench.exists() else None
        with tempfile.TemporaryDirectory() as root:
            cl.ContestExperience(store_root=root).add({"t": "x"})
        after = bench.read_bytes() if bench.exists() else None
        self.assertEqual(before, after)


class TestRunDirLayout(unittest.TestCase):
    def test_contest_run_dir(self):
        with tempfile.TemporaryDirectory() as root:
            d = cl.contest_run_dir("run42", store_root=root)
            self.assertEqual(d, Path(root) / "contest" / "run42")
            self.assertTrue(d.is_dir())


class TestGovernanceUntouched(unittest.TestCase):
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
