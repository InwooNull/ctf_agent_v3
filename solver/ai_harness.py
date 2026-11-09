"""AI/LLM-security attack harness — the attack loop over a Target.

One attempt = write a payload, send it to the Target (local mock or remote chalsrv),
observe the Verdict (ALLOW/BLOCK, whether the forbidden action ran, the output/flag),
and record it. A campaign iterates payloads until the forbidden action is observed or
the list is exhausted. Logging follows the house rules: append-only JSONL, and the
flag is NEVER written in the clear — only its sha256 and a redacted output excerpt.

Evidence discipline (mirrors solver/verifier.py and the SubmitGate contract):
  * a VERIFIED candidate is produced ONLY when we actually OBSERVED the forbidden
    action execute and the flag was emitted (evidence = that recorded attempt);
  * a flag-shaped string WITHOUT an executed forbidden action is FLAG_WITHOUT_SOLUTION
    (an UNVERIFIED candidate — never submittable);
  * a BLOCK / deterministic refusal yields no candidate at all.

Submission is NOT done here. The harness returns Candidate records; only the
orchestrator's SubmitGate may submit them (sub-agents can only report). This module
never imports a live submit path.
"""
import hashlib
import json
import re
import time
from pathlib import Path

from schemas.records import Candidate

SOLVED = "SOLVED"
FLAG_WITHOUT_SOLUTION = "FLAG_WITHOUT_SOLUTION"
REFUSED = "REFUSED"          # target blocked / grounded refusal (expected negative)
_OUTPUT_EXCERPT = 400


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _redact(text, flag):
    """Keep an output excerpt for forensics but never leak the flag in the clear."""
    text = text or ""
    if flag and flag in text:
        text = text.replace(flag, f"<FLAG:{_sha(flag)[:12]}>")
    return text[:_OUTPUT_EXCERPT]


class AttackHarness:
    def __init__(self, target, run_dir, clock=time.time):
        self.target = target
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.attempts_path = self.run_dir / "attempts.jsonl"
        self.events_path = self.run_dir / "events.jsonl"
        self._clock = clock
        self._seq = 0

    # ---- logging --------------------------------------------------------
    def _append(self, path, obj):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def _event(self, kind, **kw):
        self._append(self.events_path, {"ts": self._clock(), "kind": kind, **kw})

    # ---- one attempt ----------------------------------------------------
    def attempt(self, payload, note=""):
        """Send one payload, classify, and record. Returns the attempt record dict."""
        self._seq += 1
        aid = f"A{self._seq}"
        verdict = self.target.send(payload)
        outcome = self._classify(verdict)
        rec = {
            "id": aid,
            "ts": self._clock(),
            "subtype": getattr(self.target, "subtype", "ai"),
            "note": note,
            "decision": verdict.decision,
            "executed": verdict.executed,
            "outcome": outcome,
            "flag_present": verdict.flag is not None,
            "flag_sha256": _sha(verdict.flag) if verdict.flag else None,
            "output_excerpt": _redact(verdict.output, verdict.flag),
            "raw": verdict.raw,
        }
        self._append(self.attempts_path, rec)
        self._event("attempt", id=aid, decision=verdict.decision,
                    executed=verdict.executed, outcome=outcome)
        # keep the (unredacted) flag out of the on-disk record but available in-memory
        rec["_flag"] = verdict.flag
        return rec

    @staticmethod
    def _classify(verdict):
        if verdict.executed and verdict.flag:
            return SOLVED
        if verdict.flag and not verdict.executed:
            return FLAG_WITHOUT_SOLUTION
        if verdict.decision == "BLOCK":
            return REFUSED
        return "no-op"

    # ---- candidate ------------------------------------------------------
    def candidate_from(self, rec):
        """Build a Candidate from an attempt record, with the correct status.

        Only a SOLVED attempt yields a submittable (VERIFIED) candidate whose evidence
        is that attempt id. A flag-without-solution yields an UNVERIFIED candidate that
        the SubmitGate will refuse. Anything else yields None.
        """
        if rec.get("outcome") == SOLVED and rec.get("_flag"):
            return Candidate(value=rec["_flag"], confidence=0.95,
                             evidence_refs=[rec["id"]], status="VERIFIED")
        if rec.get("outcome") == FLAG_WITHOUT_SOLUTION and rec.get("_flag"):
            return Candidate(value=rec["_flag"], confidence=0.2,
                             evidence_refs=[rec["id"]], status="UNVERIFIED")
        return None

    # ---- campaign -------------------------------------------------------
    def run_campaign(self, payloads):
        """Iterate (note, payload) pairs until a forbidden action is observed.

        Returns {"solved": bool, "candidate": Candidate|None, "attempts": int,
                 "records": [...], "observed": [outcomes...]}.
        Deterministic refusals are recorded, not retried as if transient.
        """
        records, observed = [], []
        self._event("campaign_start", n=len(payloads),
                    subtype=getattr(self.target, "subtype", "ai"))
        for item in payloads:
            note, payload = item if isinstance(item, tuple) else ("", item)
            rec = self.attempt(payload, note=note)
            records.append(rec)
            observed.append(rec["outcome"])
            if rec["outcome"] == SOLVED:
                cand = self.candidate_from(rec)
                self._event("forbidden_action_observed", id=rec["id"])
                self._event("campaign_end", solved=True, attempts=len(records))
                return {"solved": True, "candidate": cand, "attempts": len(records),
                        "records": records, "observed": observed}
        self._event("campaign_end", solved=False, attempts=len(records))
        return {"solved": False, "candidate": None, "attempts": len(records),
                "records": records, "observed": observed}
