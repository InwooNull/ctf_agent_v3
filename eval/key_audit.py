"""Anti-ghost key-audit queue (Phase 47a) — ORCHESTRATOR-ONLY.

When a solver produces a flag backed by a STRONG evidence chain (an in-container
experiment actually printed it) that nonetheless MISMATCHES the scorer key, do not just
count it as a silent failure: log it to a key-audit queue for a human to check whether
the BENCHMARK KEY is wrong (as opposed to the solver). This is how the Phase-45/46c
mr_de0abb situation (a real, verifier-confirmed mismatch) would have been surfaced
automatically instead of only being noticed by eye.

Blindness is preserved: the SOLVER never sees the key or this queue. Only the orchestrator
grade step (which already reads the key to score) calls `audit_run(...)`, passing the key
it already holds. This module does NOT modify solver/verifier.py (a governance file) — the
verifier still returns its blind verdict unchanged; this is an additive side-log.

An entry is queued ONLY when ALL hold:
  * the run has a container evidence chain (a sandbox experiment printed the candidate),
  * the verdict is a genuine mismatch (WRONG_FLAG / UNVERIFIED — a real, evidenced
    candidate that just does not equal the key), NOT flag-without-solution (a guess with
    no evidence) and NOT solved,
  * candidate != key.
A guessed flag (FWS, no evidence) is NOT a key-audit case — it is a plain solver failure.
"""
import json
from pathlib import Path

# verdicts that represent "an evidenced candidate that does not match the key"
_MISMATCH_VERDICTS = {"WRONG_FLAG", "UNVERIFIED"}


def _norm(flag):
    return (flag or "").strip()


def audit_run(*, cid, candidate, key_flag, verdict, has_container_evidence):
    """Return a key-audit entry dict if this run is a strong-evidence mismatch, else None.
    Pure (no I/O) so it is trivially testable; the orchestrator decides whether to enqueue."""
    if not candidate or not key_flag:
        return None
    if verdict not in _MISMATCH_VERDICTS:
        return None
    if not has_container_evidence:
        return None                      # a guess / no evidence -> plain failure, not a key case
    if _norm(candidate) == _norm(key_flag):
        return None                      # matches the key -> not a mismatch
    return {"cid": cid, "candidate": _norm(candidate), "verdict": verdict,
            "reason": "strong in-container evidence chain produced a flag that mismatches the "
                      "scorer key — queue for human key verification (solver stays blind)"}


def enqueue(entry, queue_path):
    """Append an audit entry to the orchestrator-only key-audit queue (jsonl). No-op on None."""
    if entry is None:
        return False
    p = Path(queue_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return True
