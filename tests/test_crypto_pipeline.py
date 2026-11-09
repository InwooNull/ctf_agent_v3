"""Phase 3: crypto solving pipeline (scripted driver, no LLM).

Container-dependent tests auto-skip if the crypto image is not built locally.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solver import scripted_driver, verifier  # noqa: E402
from solver.crypto_harness import CryptoHarness, CRYPTO_IMAGE  # noqa: E402
from tools import sandbox  # noqa: E402

PROJECT = Path(__file__).resolve().parents[1]
DATASETS = PROJECT / "eval" / "datasets" / "dev"
# test-only copy of the Phase 3 plumbing fixtures' keys (never measured), so the suite
# does not depend on eval/scorer_keys, which is chmod 000 during measurement batches
SCORER_KEYS = PROJECT / "tests" / "fixtures" / "scorer_keys"
IMAGE_READY = sandbox.docker_available() and sandbox.image_available(CRYPTO_IMAGE)


def expected_flag(cid):
    # grader side only; solver code never does this
    return json.loads((SCORER_KEYS / f"{cid}.json").read_text())["flag"]


@unittest.skipUnless(IMAGE_READY, f"{CRYPTO_IMAGE} not built locally")
class ImageTest(unittest.TestCase):
    def test_crypto_libraries_import_in_container(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("img-check", DATASETS / "ch1_encoding", store_root=store)
            code = ("import Crypto, gmpy2, sympy, z3\n"
                    "print('IMPORTS_OK', Crypto.__version__, sympy.__version__)")
            out = h.run_experiment({"name": "imports", "code": code, "timeout": 60})
            self.assertEqual(out.execution_status, "ok")
            self.assertIn("IMPORTS_OK", out.stdout)
            self.assertEqual(out.sandbox_profile, "container")


@unittest.skipUnless(IMAGE_READY, f"{CRYPTO_IMAGE} not built locally")
class PositiveSolveTest(unittest.TestCase):
    def _solve(self, cid):
        self.store = tempfile.TemporaryDirectory()
        self.addCleanup(self.store.cleanup)
        return scripted_driver.solve(DATASETS / cid, f"run-{cid}", store_root=self.store.name)

    def test_ch1_solved_with_evidence(self):
        h, out, flag = self._solve("ch1_encoding")
        self.assertEqual(out.execution_status, "ok")
        self.assertIn(flag, out.stdout)                       # flag produced by the container
        v = verifier.verify(h.run_dir, "ch1_encoding", scorer_keys_dir=SCORER_KEYS)
        self.assertEqual(v["verdict"], verifier.SOLVED)
        self.assertTrue(v["solved"])
        self.assertEqual(v["evidence_exp_id"], out.exp_id)

    def test_ch2_solved_with_evidence(self):
        h, out, flag = self._solve("ch2_smallrsa")
        self.assertEqual(out.execution_status, "ok")
        self.assertIn(flag, out.stdout)
        v = verifier.verify(h.run_dir, "ch2_smallrsa", scorer_keys_dir=SCORER_KEYS)
        self.assertEqual(v["verdict"], verifier.SOLVED)

    def test_experiments_ran_in_container_network_off(self):
        h, out, flag = self._solve("ch1_encoding")
        self.assertEqual(out.sandbox_profile, "container")
        self.assertTrue(out.network_guaranteed)               # --network none
        # outputs confined to the per-experiment work dir
        self.assertTrue((h.work_dir / "solve").exists())


@unittest.skipUnless(IMAGE_READY, f"{CRYPTO_IMAGE} not built locally")
class NegativeTest(unittest.TestCase):
    def test_guess_without_evidence_is_flag_without_solution(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("guess-run", DATASETS / "ch1_encoding", store_root=store)
            # a correct-looking guess with NO container experiment behind it
            h.report_candidate(expected_flag("ch1_encoding"), evidence_refs=[])
            v = verifier.verify(h.run_dir, "ch1_encoding", scorer_keys_dir=SCORER_KEYS)
            self.assertEqual(v["verdict"], verifier.FLAG_WITHOUT_SOLUTION)
            self.assertFalse(v["solved"])

    def test_evidence_that_did_not_output_flag_rejected(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("badref-run", DATASETS / "ch1_encoding", store_root=store)
            out = h.run_experiment({"name": "noise", "code": "print('nothing useful here')", "timeout": 30})
            h.report_candidate(expected_flag("ch1_encoding"), evidence_refs=[out.exp_id])
            v = verifier.verify(h.run_dir, "ch1_encoding", scorer_keys_dir=SCORER_KEYS)
            self.assertEqual(v["verdict"], verifier.FLAG_WITHOUT_SOLUTION)


@unittest.skipUnless(IMAGE_READY, f"{CRYPTO_IMAGE} not built locally")
class IsolationAndLeakTest(unittest.TestCase):
    def test_write_outside_workdir_blocked(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("iso-run", DATASETS / "ch1_encoding", store_root=store)
            out = h.run_experiment({"name": "escape",
                                    "code": "open('/root_escape','w').write('x');print('WROTE')",
                                    "timeout": 30})
            self.assertNotEqual(out.execution_status, "ok")
            self.assertNotIn("WROTE", out.stdout)

    def test_scorer_keys_not_reachable_from_container(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("leak-run", DATASETS / "ch2_smallrsa", store_root=store)
            code = (
                "import os\n"
                "guesses = ['/input/ch2_smallrsa.json', '/scorer_keys/ch2_smallrsa.json',\n"
                "           '/input/../scorer_keys/ch2_smallrsa.json', '/work/../scorer_keys/ch2_smallrsa.json']\n"
                "reachable = [p for p in guesses if os.path.exists(p)]\n"
                "print('REACHABLE', reachable)\n"
                "mounts = open('/proc/mounts').read()\n"
                "print('MOUNT_SCORER', 'scorer' in mounts.lower())\n"
                "print('INPUT', sorted(os.listdir('/input')))")
            out = h.run_experiment({"name": "leakprobe", "code": code, "timeout": 30})
            self.assertEqual(out.execution_status, "ok")
            self.assertIn("REACHABLE []", out.stdout)
            self.assertIn("MOUNT_SCORER False", out.stdout)
            self.assertNotIn("scorer_keys", out.stdout.replace("MOUNT_SCORER", ""))

    def test_challenge_dir_contains_no_scorer_key(self):
        # host-side: the mounted input dir must not carry the answer
        for cid in ("ch1_encoding", "ch2_smallrsa"):
            files = {p.name for p in (DATASETS / cid).iterdir()}
            self.assertNotIn(f"{cid}.json", files - {"challenge.json"})
            self.assertFalse(any("scorer" in f for f in files))


@unittest.skipUnless(IMAGE_READY, f"{CRYPTO_IMAGE} not built locally")
class BudgetDedupTest(unittest.TestCase):
    def test_dedup_on_container_path(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("dedup-run", DATASETS / "ch1_encoding", store_root=store)
            spec = {"name": "solve", "code": "print('hello-dedup')", "timeout": 30}
            o1 = h.run_experiment(dict(spec))
            o2 = h.run_experiment(dict(spec))
            self.assertFalse(o1.cached)
            self.assertTrue(o2.cached)                        # served from cache, no re-run
            self.assertEqual(o1.dedup_key, o2.dedup_key)
            self.assertEqual(h.budget_spent["attempts"], 1)   # only one real container run
            self.assertEqual(o1.stdout, o2.stdout)

    def test_nondeterministic_not_cached(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("nd-run", DATASETS / "ch1_encoding", store_root=store)
            spec = {"name": "solve", "code": "print('x')", "timeout": 30, "nondeterministic": True}
            h.run_experiment(dict(spec))
            o2 = h.run_experiment(dict(spec))
            self.assertFalse(o2.cached)
            self.assertEqual(h.budget_spent["attempts"], 2)

    def test_budget_blocks_container_run(self):
        with tempfile.TemporaryDirectory() as store:
            h = CryptoHarness("budget-run", DATASETS / "ch1_encoding", store_root=store,
                              budget={"time_s": 300, "max_attempts": 0})
            out = h.run_experiment({"name": "solve", "code": "print('should not run')", "timeout": 30})
            self.assertEqual(out.execution_status, "aborted")
            self.assertEqual(h.budget_spent["attempts"], 0)
            events = [json.loads(l) for l in (h.run_dir / "events.jsonl").read_text().splitlines()]
            self.assertTrue(any(e["kind"] == "experiment_blocked" for e in events))


if __name__ == "__main__":
    unittest.main()
