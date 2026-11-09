"""AI/ML-security sub-harness — model-file / adversarial-ML attacks.

The model-file axis of the AI category (see docs/mlsec_category.md): load a model
(.pt / .safetensors / .onnx), run inference, and mount an attack — an adversarial
perturbation (FGSM/PGD), a weight manipulation, or a query/optimization against a
scorer — then observe whether the success condition (a scorer threshold passed, a
targeted misclassification confirmed) actually holds.

It reuses the container-run plumbing of CryptoHarness unchanged (every attack runs
inside the ctfagent-mlsec image, --network none, read-only root, non-root, rlimited):
the attack produces an ARTIFACT (a perturbed input / recovered value) into the run's
/work bind mount. The flag is NOT mounted into the container, so the attack code can
never read it — success is confirmed by a trusted SCORER that holds the flag:

  RemoteScorer           interface: score(artifact_path) -> {passed, flag, detail}
  MockScorer             local deterministic scorer (holds the injected vault flag,
                         runs a public checker over the artifact) — for synthetic proofs
  ChalsrvScorer          wraps connector.chalsrv for a live/recorded challenge server

Evidence discipline (same as solver.ai_harness / the SubmitGate contract): a candidate
is VERIFIED only when the scorer actually ACCEPTED an artifact our container produced
(evidence = [that container experiment, the scorer verdict]); an artifact that does not
pass, or a flag not emitted by the scorer, is never a verified candidate (no guessing).
Submission is never done here — the orchestrator's SubmitGate submits; sub-agents report.
"""
import json
import time
from pathlib import Path

from solver.crypto_harness import CryptoHarness
from schemas.records import Candidate

MLSEC_IMAGE = "ctfagent-mlsec:0.1"
# torch needs far more than the 256m crypto default; raise the mlsec container limits.
MLSEC_LIMITS = {"memory": "2g", "cpus": "1.0", "pids_limit": 256, "fsize_bytes": 67108864}

# Arbitrary python, untrusted -> pinned to the container backend, mlsec lane.
MLSEC_ALLOWLIST = {
    "pycode": {"bin": "python3", "version_cmd": None, "smoke_cmd": None,
               "deterministic": True, "trust": "untrusted", "categories": ["mlsec"],
               "sandbox_profile": "container"},
}

VERIFIED = "VERIFIED"
UNVERIFIED = "UNVERIFIED"
FLAG_WITHOUT_SOLUTION = "FLAG_WITHOUT_SOLUTION"


# --------------------------------------------------------------------------
# Scorer abstraction
# --------------------------------------------------------------------------
class RemoteScorer:
    """Interface: score(artifact_path) -> {"passed": bool, "flag": str|None, "detail": ...}."""
    def score(self, artifact_path):  # pragma: no cover - interface
        raise NotImplementedError


class MockScorer(RemoteScorer):
    """Local deterministic scorer: runs a public `checker(artifact_path)->bool` and,
    only if it passes, returns the injected (secret) flag. The flag is held by the
    scorer, never by the attack container.
    """
    def __init__(self, checker, flag):
        if not flag:
            raise ValueError("MockScorer requires an injected flag")
        self._checker = checker
        self._flag = flag
        self.calls = 0

    def score(self, artifact_path):
        self.calls += 1
        try:
            passed = bool(self._checker(artifact_path))
        except Exception as e:  # a malformed artifact is simply "not passed"
            return {"passed": False, "flag": None, "detail": f"checker error: {e}"}
        return {"passed": passed, "flag": self._flag if passed else None,
                "detail": "accepted" if passed else "below threshold / wrong class"}


class ChalsrvScorer(RemoteScorer):
    """Wrap a connector.chalsrv server as a scorer (live/recorded). Offline-untested."""
    def __init__(self, submit_fn, flag_key="flag"):
        self._submit = submit_fn
        self._flag_key = flag_key

    def score(self, artifact_path):
        resp = self._submit(Path(artifact_path).read_bytes())
        passed = bool(resp.get("passed") or resp.get("solved") or resp.get("success"))
        return {"passed": passed, "flag": resp.get(self._flag_key) if passed else None,
                "detail": resp.get("status")}


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
class MlsecHarness(CryptoHarness):
    def __init__(self, run_id, challenge_dir, store_root=None, budget=None,
                 image=MLSEC_IMAGE, clock=None):
        super().__init__(run_id, challenge_dir, store_root=store_root, budget=budget,
                         image=image, clock=clock)
        self.allowlist = MLSEC_ALLOWLIST
        self.sandbox_config["container"]["limits"] = dict(MLSEC_LIMITS)
        self._scored = []  # append-only scorer observations (no plaintext flag)

    def score_artifact(self, exp_id, artifact_rel, scorer):
        """Submit a container-produced artifact to the scorer and record the verdict.

        `artifact_rel` is a path relative to this experiment's work dir. Returns the
        scorer verdict dict augmented with the producing experiment id.
        """
        artifact_path = self.work_dir / exp_id.replace(f"{self.challenge_id}-", "") / artifact_rel
        if not artifact_path.is_file():
            # fall back to a direct path under work_dir (caller may pass a full rel path)
            artifact_path = self.work_dir / artifact_rel
        verdict = scorer.score(str(artifact_path))
        rec = {"ts": time.time(), "exp_id": exp_id, "artifact": str(artifact_rel),
               "passed": verdict["passed"], "flag_present": verdict["flag"] is not None,
               "detail": verdict.get("detail")}
        self._scored.append(rec)
        with open(self.run_dir / "scored.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.elog.append_event("artifact_scored", exp_id=exp_id, passed=verdict["passed"],
                               flag_present=verdict["flag"] is not None)
        verdict = dict(verdict)
        verdict["exp_id"] = exp_id
        return verdict

    def candidate_from_score(self, exp_outcome, verdict):
        """Build a Candidate from a scorer verdict + the producing container experiment.

        VERIFIED only when the scorer accepted the artifact (passed + flag) AND the
        producing experiment actually ran in the container. Otherwise no candidate
        (a non-passing artifact) — never a guess.
        """
        ran = exp_outcome.execution_status in ("ok", "error", "timeout") \
            and exp_outcome.sandbox_profile == "container"
        if verdict.get("passed") and verdict.get("flag") and ran:
            cand = Candidate(value=verdict["flag"], confidence=0.95,
                             evidence_refs=[exp_outcome.exp_id], status=VERIFIED)
            # mirror into candidates.jsonl (status recorded, value kept for the gate)
            self._log_candidate(cand)
            return cand
        if verdict.get("flag") and not ran:
            cand = Candidate(value=verdict["flag"], confidence=0.1,
                             evidence_refs=[exp_outcome.exp_id], status=UNVERIFIED)
            self._log_candidate(cand)
            return cand
        return None

    def _log_candidate(self, cand):
        with open(self.run_dir / "candidates.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"value": cand.value, "evidence_refs": cand.evidence_refs,
                                "status": cand.status}, sort_keys=True) + "\n")
        self.elog.append_event("candidate", status=cand.status, evidence_refs=cand.evidence_refs)
