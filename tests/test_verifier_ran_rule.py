"""Phase 7 regression: evidence = an experiment that actually RAN printed the flag.

Exit code / crash after printing does not matter (ok | error | timeout count);
experiments that never ran normally (aborted, budget-blocked, no execution) never count.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solver import verifier  # noqa: E402
from solver.crypto_harness import CryptoHarness, CRYPTO_IMAGE  # noqa: E402
from tools import sandbox  # noqa: E402

PROJECT = Path(__file__).resolve().parents[1]
CH1 = PROJECT / "eval" / "datasets" / "dev" / "ch1_encoding"
SCORER_KEYS = PROJECT / "tests" / "fixtures" / "scorer_keys"   # test-only copy, independent of the vault lock
IMAGE_READY = sandbox.docker_available() and sandbox.image_available(CRYPTO_IMAGE)
FLAG = "FLAG{unit_test_flag}"


def fake_run(tmp, status, profile="container", printed=True, blocked=False):
    """Synthetic run dir + scorer key, so the rule is tested without docker."""
    run = Path(tmp) / "run"
    (run / "artifacts").mkdir(parents=True)
    keys = Path(tmp) / "keys"
    keys.mkdir()
    (keys / "cX.json").write_text(json.dumps({"flag": FLAG}))
    (run / "artifacts" / "e1.stdout").write_text((FLAG if printed else "nothing") + "\nTraceback ...\n")
    rec = {"exp_id": "e1", "execution_status": status, "sandbox_profile": profile,
           "stdout_ref": "" if blocked else "artifacts/e1.stdout"}
    if blocked:
        rec["blocked_by"] = "max_attempts"
    (run / "experiments.jsonl").write_text(json.dumps(rec) + "\n")
    (run / "candidates.jsonl").write_text(json.dumps({"value": FLAG, "evidence_refs": ["e1"]}) + "\n")
    return verifier.verify(run, "cX", scorer_keys_dir=keys)["verdict"]


class RanRuleUnitTest(unittest.TestCase):
    def test_ok_counts(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(fake_run(t, "ok"), verifier.SOLVED)

    def test_crash_after_print_counts(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(fake_run(t, "error"), verifier.SOLVED)

    def test_timeout_after_print_counts(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(fake_run(t, "timeout"), verifier.SOLVED)

    def test_aborted_not_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(fake_run(t, "aborted"), verifier.FLAG_WITHOUT_SOLUTION)

    def test_blocked_not_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(fake_run(t, "aborted", profile="none", blocked=True),
                             verifier.FLAG_WITHOUT_SOLUTION)

    def test_non_container_not_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(fake_run(t, "ok", profile="readonly-utils"), verifier.FLAG_WITHOUT_SOLUTION)

    def test_run_without_flag_not_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(fake_run(t, "error", printed=False), verifier.FLAG_WITHOUT_SOLUTION)


@unittest.skipUnless(IMAGE_READY, f"{CRYPTO_IMAGE} not built locally")
class RanRuleContainerTest(unittest.TestCase):
    """End to end through the real harness + container."""

    def setUp(self):
        self.store = tempfile.TemporaryDirectory()
        self.addCleanup(self.store.cleanup)
        # grader side only: the test needs the answer to plant "print then crash"
        self.flag = json.loads((SCORER_KEYS / "ch1_encoding.json").read_text())["flag"]

    def test_crash_after_print_is_solved(self):
        h = CryptoHarness("ran-crash", CH1, store_root=self.store.name)
        code = f"import sys\nprint({self.flag!r}, flush=True)\nraise RuntimeError('crash after print')\n"
        out = h.run_experiment({"name": "crash", "code": code})
        self.assertEqual(out.execution_status, "error")
        h.report_candidate(self.flag, [out.exp_id])
        self.assertEqual(verifier.verify(h.run_dir, "ch1_encoding", scorer_keys_dir=SCORER_KEYS)["verdict"], verifier.SOLVED)

    def test_budget_blocked_experiment_not_evidence(self):
        h = CryptoHarness("ran-blocked", CH1, store_root=self.store.name,
                          budget={"time_s": 300, "max_attempts": 0})
        out = h.run_experiment({"name": "blocked", "code": f"print({self.flag!r})\n"})
        self.assertEqual(out.sandbox_profile, "none")
        h.report_candidate(self.flag, [out.exp_id])
        self.assertEqual(verifier.verify(h.run_dir, "ch1_encoding", scorer_keys_dir=SCORER_KEYS)["verdict"],
                         verifier.FLAG_WITHOUT_SOLUTION)


if __name__ == "__main__":
    unittest.main()
