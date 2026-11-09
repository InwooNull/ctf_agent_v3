"""Phase CM1: mode switch skeleton + single entrypoint (solve) acceptance tests.

Covers: (1) solve auto-detects the 4 input kinds, (2) contest is the default mode and
--bench is the only way into bench, (3) the mode profiles carry the right policy, and
(4) the governance 7 files are still byte-identical (bench path / isolation untouched).
"""
import hashlib
import inspect
import os
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import solve                                        # noqa: E402
from orchestrator import mode as mode_mod           # noqa: E402
from orchestrator import competition                # noqa: E402


class TestInputDetection(unittest.TestCase):
    def test_ctfd_by_token(self):
        self.assertEqual(
            solve.detect_input("https://ctf.example.com/files/abc/x.zip?token=ey.jj"),
            solve.CTFD)

    def test_ctfd_by_path(self):
        self.assertEqual(
            solve.detect_input("https://ctf.example.com/api/v2/challenges"), solve.CTFD)

    def test_ctfd_forced_flag(self):
        self.assertEqual(
            solve.detect_input("https://ctf.example.com/", ctfd=True), solve.CTFD)

    def test_plain_url_is_target(self):
        self.assertEqual(solve.detect_input("http://3.34.205.142:8000"), solve.URL)
        self.assertEqual(solve.detect_input("http://3.34.205.142:8000/img"), solve.URL)

    def test_directory(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(solve.detect_input(d), solve.DIR)

    def test_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "chal.bin")
            Path(f).write_bytes(b"\x7fELF")
            self.assertEqual(solve.detect_input(f), solve.FILE)

    def test_four_kinds_all_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "a.txt")
            Path(f).write_text("x")
            kinds = {
                solve.detect_input("https://c/api/v2/challenges"),
                solve.detect_input("http://1.2.3.4:9/"),
                solve.detect_input(d),
                solve.detect_input(f),
            }
        self.assertEqual(kinds, {solve.CTFD, solve.URL, solve.DIR, solve.FILE})

    def test_ctfd_flag_on_nonurl_raises(self):
        with self.assertRaises(ValueError):
            solve.detect_input("/tmp/whatever", ctfd=True)

    def test_unresolvable_raises(self):
        with self.assertRaises(ValueError):
            solve.detect_input("/no/such/path/really/nope")
        with self.assertRaises(ValueError):
            solve.detect_input("")


class TestModeResolution(unittest.TestCase):
    def test_default_is_contest(self):
        self.assertEqual(mode_mod.DEFAULT, mode_mod.CONTEST)
        self.assertEqual(solve.resolve_mode(bench=False), mode_mod.CONTEST)

    def test_bench_only_via_flag(self):
        self.assertEqual(solve.resolve_mode(bench=True), mode_mod.BENCH)

    def test_normalize(self):
        self.assertEqual(mode_mod.normalize(None), mode_mod.CONTEST)
        self.assertEqual(mode_mod.normalize("BENCH"), mode_mod.BENCH)
        self.assertEqual(mode_mod.normalize(" contest "), mode_mod.CONTEST)
        with self.assertRaises(ValueError):
            mode_mod.normalize("prod")

    def test_bench_profile_is_blind(self):
        p = mode_mod.profile(mode_mod.BENCH)
        self.assertEqual(p["network"], "none")
        self.assertTrue(p["use_vault"])
        self.assertEqual(p["experience_tag"], "bench")
        self.assertFalse(p["auto_submit"])

    def test_contest_profile(self):
        p = mode_mod.profile(mode_mod.CONTEST)
        self.assertEqual(p["network"], "target-only")
        self.assertFalse(p["use_vault"])
        self.assertEqual(p["experience_tag"], "contest")
        self.assertFalse(p["auto_submit"])          # never auto-submit, either mode

    def test_profile_is_a_copy(self):
        p = mode_mod.profile(mode_mod.CONTEST)
        p["network"] = "ALL"
        self.assertEqual(mode_mod.profile(mode_mod.CONTEST)["network"], "target-only")


class TestBuildPlanBranching(unittest.TestCase):
    def test_contest_default_plan(self):
        plan = solve.build_plan("https://c/api/v2/challenges")
        self.assertEqual(plan["kind"], solve.CTFD)
        self.assertEqual(plan["mode"], mode_mod.CONTEST)
        self.assertEqual(plan["network"], "target-only")
        self.assertFalse(plan["use_vault"])

    def test_bench_plan_branches(self):
        plan = solve.build_plan("https://c/api/v2/challenges", bench=True)
        self.assertEqual(plan["mode"], mode_mod.BENCH)
        self.assertEqual(plan["network"], "none")
        self.assertTrue(plan["use_vault"])

    def test_plan_never_auto_submits(self):
        for bench in (False, True):
            self.assertFalse(solve.build_plan("http://1.2.3.4/", bench=bench)["auto_submit"])

    def test_main_dry_contest(self):
        rc = solve.main(["http://1.2.3.4:8000/"])
        self.assertEqual(rc, 0)

    def test_main_bad_input(self):
        rc = solve.main(["/no/such/path/xyz"])
        self.assertEqual(rc, 2)


class TestCompetitionThreadsMode(unittest.TestCase):
    def test_competition_default_param_is_contest(self):
        sig = inspect.signature(competition.Competition.__init__)
        self.assertEqual(sig.parameters["mode"].default, mode_mod.DEFAULT)

    def test_competition_uses_mode_module(self):
        self.assertTrue(hasattr(competition, "mode_mod"))


class TestGovernanceUntouched(unittest.TestCase):
    def test_seven_files_hash_invariant(self):
        baseline = (PROJECT_ROOT / "growth" / "governance_baseline.txt").read_text().splitlines()
        self.assertEqual(len([l for l in baseline if l.strip()]), 7)
        for line in baseline:
            line = line.strip()
            if not line:
                continue
            want, rel = line.split()[0], line.split()[-1]
            got = hashlib.sha256((PROJECT_ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"governance file changed: {rel}")


if __name__ == "__main__":
    unittest.main()
