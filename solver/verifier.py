"""Verifier — the ONLY component that reads the scorer keys.

SOLVED requires both:
  (a) a reported candidate equals the scorer's expected flag, AND
  (b) an evidence chain: some recorded *container* experiment that actually
      RAN printed that flag (its captured stdout contains it). Exit code and
      crashes do not matter (status ok | error | timeout all count); experiments
      that did not run normally (aborted / blocked / no execution) never count.

  (a) without (b) -> FLAG_WITHOUT_SOLUTION   (a guess, not a demonstrated solve)
  neither         -> UNVERIFIED

The scorer-key read is isolated in `_expected_flag`; nothing in the solver /
harness / driver path calls it, and the keys are never mounted into a container.
"""
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCORER_KEYS = PROJECT_ROOT / "eval" / "scorer_keys"

SOLVED = "SOLVED"
FLAG_WITHOUT_SOLUTION = "FLAG_WITHOUT_SOLUTION"
UNVERIFIED = "UNVERIFIED"
# experiment statuses that mean the code actually executed to an end we accept
RAN_STATUSES = ("ok", "error", "timeout")


def _expected_flag(challenge_id, scorer_keys_dir):
    """Isolated scorer path: read the expected flag. Solver code must not call this."""
    path = Path(scorer_keys_dir) / f"{challenge_id}.json"
    return json.loads(path.read_text())["flag"]


def _read_experiments(run_dir):
    path = Path(run_dir) / "experiments.jsonl"
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        rec = json.loads(line)
        out[rec["exp_id"]] = rec
    return out


def _read_candidates(run_dir):
    path = Path(run_dir) / "candidates.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines()]


def _evidence_supports(run_dir, flag, evidence_refs, experiments):
    """True iff some referenced experiment ran in a container AND its stdout
    actually contains the flag (the flag was demonstrably produced, not guessed)."""
    artifacts = Path(run_dir) / "artifacts"
    for ref in evidence_refs:
        exp = experiments.get(ref)
        if not exp or exp.get("sandbox_profile") != "container":
            continue
        if exp.get("execution_status") not in RAN_STATUSES:
            continue
        stdout_ref = exp.get("stdout_ref")
        if not stdout_ref:
            continue
        try:
            text = (artifacts / Path(stdout_ref).name).read_text(errors="replace")
        except OSError:
            continue
        if flag in text:
            return ref
    return None


def verify(run_dir, challenge_id, scorer_keys_dir=DEFAULT_SCORER_KEYS):
    """Return a verdict dict for a harness run directory."""
    expected = _expected_flag(challenge_id, scorer_keys_dir)
    experiments = _read_experiments(run_dir)
    candidates = _read_candidates(run_dir)

    matched = [c for c in candidates if c["value"] == expected]
    if not matched:
        return {"verdict": UNVERIFIED, "challenge_id": challenge_id, "solved": False,
                "reason": "no candidate matches the expected flag"}
    for cand in matched:
        ev = _evidence_supports(run_dir, expected, cand.get("evidence_refs", []), experiments)
        if ev is not None:
            return {"verdict": SOLVED, "challenge_id": challenge_id, "solved": True,
                    "evidence_exp_id": ev, "flag": expected}
    return {"verdict": FLAG_WITHOUT_SOLUTION, "challenge_id": challenge_id, "solved": False,
            "reason": "flag matches but no container experiment produced it"}
