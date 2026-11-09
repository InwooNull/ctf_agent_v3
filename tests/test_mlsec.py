"""mlsec sub-harness plumbing tests.

Unit tests (no docker, no vault) cover the scorer + candidate/evidence logic and the
classifier wiring. One end-to-end test runs a real attack inside the ctfagent-mlsec
container and scores it with a TEST flag (so it needs no vault secret); it is skipped
if the image is absent.
"""
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from solver.mlsec_harness import MlsecHarness, MockScorer, RemoteScorer  # noqa: E402
from solver.crypto_harness import ExperimentOutcome                      # noqa: E402
from orchestrator.classifier import classify                            # noqa: E402
from orchestrator.router import route                                   # noqa: E402
from tools import sandbox                                               # noqa: E402

MLSEC_IMAGE = "ctfagent-mlsec:0.1"
ARENA = PROJECT_ROOT / "arena" / "mlsec"
TEST_FLAG = "FLAG{mlsec_test_e2e}"


def _harness(sid="mls_s1"):
    return MlsecHarness(f"t_{sid}", ARENA / sid, store_root=Path(tempfile.mkdtemp()))


def _container_ran(exp_id="mls_s1-attack"):
    return ExperimentOutcome(exp_id, "ok", "", "r", "container", True, "k", False)


class Scorer(unittest.TestCase):
    def test_mock_scorer_pass_returns_flag(self):
        s = MockScorer(lambda art: True, TEST_FLAG)
        v = s.score("/nonexistent")
        self.assertTrue(v["passed"])
        self.assertEqual(v["flag"], TEST_FLAG)

    def test_mock_scorer_fail_no_flag(self):
        s = MockScorer(lambda art: False, TEST_FLAG)
        v = s.score("/x")
        self.assertFalse(v["passed"])
        self.assertIsNone(v["flag"])

    def test_mock_scorer_checker_error_is_not_pass(self):
        def boom(art): raise ValueError("bad artifact")
        v = MockScorer(boom, TEST_FLAG).score("/x")
        self.assertFalse(v["passed"])

    def test_requires_flag(self):
        with self.assertRaises(ValueError):
            MockScorer(lambda a: True, "")

    def test_remote_scorer_is_interface(self):
        with self.assertRaises(NotImplementedError):
            RemoteScorer().score("/x")


class CandidateEvidence(unittest.TestCase):
    def test_verified_requires_pass_and_container_run(self):
        h = _harness()
        cand = h.candidate_from_score(_container_ran(),
                                      {"passed": True, "flag": TEST_FLAG})
        self.assertEqual(cand.status, "VERIFIED")
        self.assertEqual(cand.evidence_refs, ["mls_s1-attack"])

    def test_pass_but_no_real_run_is_unverified(self):
        h = _harness()
        no_run = ExperimentOutcome("mls_s1-attack", "aborted", "", "", "none", False, "", False)
        cand = h.candidate_from_score(no_run, {"passed": True, "flag": TEST_FLAG})
        self.assertEqual(cand.status, "UNVERIFIED")

    def test_non_pass_yields_no_candidate(self):
        h = _harness()
        self.assertIsNone(h.candidate_from_score(_container_ran(),
                                                 {"passed": False, "flag": None}))

    def test_mem_limit_raised_for_torch(self):
        h = _harness()
        self.assertEqual(h.sandbox_config["container"]["limits"]["memory"], "2g")
        self.assertEqual(h.allowlist["pycode"]["categories"], ["mlsec"])


class CategoryWiring(unittest.TestCase):
    def test_model_file_classifies_ai(self):
        self.assertEqual(classify({"name": "weights", "description": "", "files": ["model.pt"]}), "ai")
        self.assertEqual(classify({"name": "x", "description": "", "files": ["m.onnx"]}), "ai")

    def test_adversarial_keyword_ai(self):
        self.assertEqual(classify({"name": "Misread",
                                   "description": "craft an adversarial example to fool the classifier model",
                                   "files": []}), "ai")

    def test_route_ai(self):
        self.assertEqual(route("ai"), "ai_lane")


@unittest.skipUnless(sandbox.image_available(MLSEC_IMAGE), f"{MLSEC_IMAGE} not present")
class ContainerE2E(unittest.TestCase):
    def test_adversarial_solve_in_container(self):
        import importlib.util
        sid = "mls_s1"
        h = _harness(sid)
        # inline attack so the test does not depend on vault being unlocked
        attack = (
            'import json,numpy as np,torch\n'
            'd=np.load("/input/data.npz");m=json.load(open("/input/meta.json"))\n'
            'W,b,x0=d["W"],d["b"],d["x0"].astype("float64")\n'
            't,tr,eps=m["target_class"],m["true_class"],m["eps"]\n'
            'x=torch.tensor(x0,requires_grad=True)\n'
            'L=(torch.tensor(W)@x+torch.tensor(b))[t]-(torch.tensor(W)@x+torch.tensor(b))[tr]\n'
            'L.backward()\n'
            'np.save("artifact.npy",x0+eps*torch.sign(x.grad).detach().numpy())\n'
            'print("done")\n'
        )
        out = h.run_experiment({"name": "attack", "code": attack, "timeout": 180})
        self.assertEqual(out.execution_status, "ok")
        self.assertEqual(out.sandbox_profile, "container")
        self.assertTrue(out.network_guaranteed)

        spec = importlib.util.spec_from_file_location("ck", ARENA / sid / "checker.py")
        ck = importlib.util.module_from_spec(spec); spec.loader.exec_module(ck)
        scorer = MockScorer(lambda art: ck.check(art, str(ARENA / sid)), TEST_FLAG)
        verdict = h.score_artifact(out.exp_id, "artifact.npy", scorer)
        self.assertTrue(verdict["passed"])
        cand = h.candidate_from_score(out, verdict)
        self.assertEqual(cand.status, "VERIFIED")
        self.assertEqual(cand.value, TEST_FLAG)


if __name__ == "__main__":
    unittest.main()
