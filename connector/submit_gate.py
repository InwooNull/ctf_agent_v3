"""SubmitGate — the single governed chokepoint for flag submission.

The most expensive mistake of the ACDC quals was delegating submit rights to a
sub-agent, which then sprayed ~20 blind wrong guesses at one challenge and got the
whole account rate-limited. The fix is a hard architectural rule, enforced in code
here rather than by convention:

    Sub-agents may only REPORT candidates. Only the orchestrator submits.

A sub-agent is handed a gate built with `SubmitGate.for_subagent()`: it has role
"subagent" and literally holds no network client, so `submit_candidate()` raises
`NotAuthorized` and there is no other path from sub-agent code to the live POST.
It can call `report_candidate()`, which only appends to an in-memory queue.

The orchestrator builds `SubmitGate.for_orchestrator(client, ...)` and submits
through `submit_candidate()`, which enforces, in order:

  (a) role is orchestrator                         -> else NotAuthorized
  (b) the candidate passed our evidence chain      -> else UnverifiedCandidate
      (status == VERIFIED *and* it carries evidence_refs: a produced flag, not a guess)
  (c) not a duplicate flag, and the challenge is not already solved
                                                    -> else DuplicateSubmission
  (d) the per-challenge attempt cap is not reached  -> else AttemptCapReached
  then POSTs with rate-limit backoff, and appends an append-only log line.

The log (store/live/submissions.jsonl by default) records only the flag's sha256,
never the flag, so the store stays scrub-safe. Gate state (what was tried / solved
per challenge, attempt counts) is rebuilt from that log on construction, so a crash
or a fresh process never double-submits or loses the cap.
"""
import hashlib
import json
import time
from pathlib import Path

from connector.ctfd_client import RateLimited
from connector.retry import Backoff

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = PROJECT_ROOT / "store" / "live" / "submissions.jsonl"

ORCHESTRATOR = "orchestrator"
SUBAGENT = "subagent"

# outcomes that mean the POST was scored (consumes an attempt / guess)
SCORED_STATUSES = ("correct", "incorrect", "already_solved")


class SubmitGateError(RuntimeError):
    pass


class NotAuthorized(SubmitGateError):
    """A non-orchestrator role tried to submit."""


class UnverifiedCandidate(SubmitGateError):
    """The candidate did not pass our evidence chain."""


class DuplicateSubmission(SubmitGateError):
    """This flag was already tried, or the challenge is already solved."""


class AttemptCapReached(SubmitGateError):
    """The per-challenge scored-attempt cap is reached."""


class DecoyRejected(SubmitGateError):
    """The candidate value looks like a decoy / placeholder (e.g. 'SAMPLE FLAG')."""


class ReproductionFailed(SubmitGateError):
    """A clean reproduction did not re-derive the same flag, so we do not submit."""


def _sha(flag):
    return hashlib.sha256(flag.encode("utf-8")).hexdigest()


class SubmitGate:
    def __init__(self, client=None, role=SUBAGENT, log_path=DEFAULT_LOG,
                 max_attempts_per_challenge=5, max_429_retries=4,
                 sleep=time.sleep, clock=time.time,
                 decoy_check=None, reproducer=None):
        self.client = client
        self.role = role
        self.log_path = Path(log_path)
        self.max_attempts = max_attempts_per_challenge
        self.max_429_retries = max_429_retries
        self._sleep = sleep
        self._clock = clock
        # Optional orchestrator-injected gates (Phase 29). Both default off so the
        # gate behaves exactly as before unless the orchestrator wires them in.
        #   decoy_check(value, evidence_refs) -> True if the value is a decoy.
        #   reproducer(cid, candidate) -> {"ok": bool, "flag": str, "evidence": ...}
        #     a clean, history-free re-derivation of the flag. Must return ok AND the
        #     same flag before a candidate is submitted.
        self.decoy_check = decoy_check
        self.reproducer = reproducer
        self._candidates = {}   # cid -> list[Candidate]   (reported, not yet submitted)
        # per-cid submission state, rebuilt from the append-only log:
        self._tried_sha = {}    # cid -> set(flag_sha256) scored (dup guard)
        self._scored = {}       # cid -> count of scored attempts (cap)
        self._solved = set()    # cids with a 'correct'
        self._replay_log()

    # ---- constructors ---------------------------------------------------
    @classmethod
    def for_orchestrator(cls, client, **kw):
        if client is None:
            raise SubmitGateError("orchestrator gate requires a client")
        return cls(client=client, role=ORCHESTRATOR, **kw)

    @classmethod
    def for_subagent(cls, **kw):
        # no client: a sub-agent gate physically cannot reach the network
        kw.pop("client", None)
        return cls(client=None, role=SUBAGENT, **kw)

    # ---- state replay (crash/restart safe) ------------------------------
    def _replay_log(self):
        if not self.log_path.is_file():
            return
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            cid = row.get("cid", row.get("ctfd_id"))
            if cid is None:
                continue
            cid = str(cid)
            status = row.get("status")
            if status in SCORED_STATUSES:
                self._scored[cid] = self._scored.get(cid, 0) + 1
                sha = row.get("flag_sha256")
                if sha:
                    self._tried_sha.setdefault(cid, set()).add(sha)
                if status in ("correct", "already_solved"):
                    self._solved.add(cid)

    # ---- the candidate sink (safe for any role) -------------------------
    def report_candidate(self, cid, candidate):
        """A sub-agent (or anyone) records a candidate flag. Touches no network.

        Returns the current queue length for that challenge. This is the ONLY
        submission-adjacent call a sub-agent is allowed to make.
        """
        self._candidates.setdefault(str(cid), []).append(candidate)
        return len(self._candidates[str(cid)])

    def reported(self, cid):
        return list(self._candidates.get(str(cid), []))

    # ---- evidence chain -------------------------------------------------
    @staticmethod
    def is_submittable(candidate):
        """Our evidence chain: a candidate is submittable only if it is VERIFIED
        *and* carries evidence_refs (it was produced by a recorded experiment, not
        typed as a blind guess). Mirrors the verifier's SOLVED discipline.
        """
        status = getattr(candidate, "status", None)
        if status is None and isinstance(candidate, dict):
            status = candidate.get("status")
            refs = candidate.get("evidence_refs") or []
        else:
            refs = getattr(candidate, "evidence_refs", []) or []
        return status == "VERIFIED" and bool(refs)

    @staticmethod
    def _value(candidate):
        if isinstance(candidate, dict):
            return candidate.get("value")
        return getattr(candidate, "value", None)

    # ---- the one outward action (orchestrator only) ---------------------
    def submit_candidate(self, cid, candidate):
        """Submit a reported candidate (the agent-pipeline path). Enforces role, the
        evidence chain, dup and cap, then POSTs with rate-limit backoff.
        Returns (status, message).
        """
        if not self.is_submittable(candidate):
            raise UnverifiedCandidate(
                "candidate failed the evidence chain (needs status=VERIFIED + evidence_refs)")
        flag = self._value(candidate)
        if not flag:
            raise UnverifiedCandidate("candidate has no flag value")
        # Phase 29: decoy screen, then reproduce-before-submit (both opt-in).
        if self.decoy_check is not None:
            refs = getattr(candidate, "evidence_refs", None)
            if refs is None and isinstance(candidate, dict):
                refs = candidate.get("evidence_refs")
            if self.decoy_check(flag, refs or []):
                raise DecoyRejected(f"candidate for {cid} looks like a decoy; not submitting")
        if self.reproducer is not None:
            rep = self.reproducer(cid, candidate) or {}
            if not rep.get("ok") or rep.get("flag") != flag:
                raise ReproductionFailed(
                    f"clean reproduction did not re-derive the flag for {cid}; not submitting")
        return self.submit_flag_value(cid, flag)

    def submit_flag_value(self, cid, flag, force=False):
        """Submit a bare flag string (the human-operator / CLI path). Skips the
        evidence-chain check — the operator asserts it — but keeps every other
        governance rule: role, dup, cap, backoff, append-only log.

        `force` is an operator override that drops the dup/already-solved guard for
        this one flag (it never drops the role check or the attempt cap).
        """
        cid = str(cid)
        if self.role != ORCHESTRATOR or self.client is None:
            raise NotAuthorized(
                f"role {self.role!r} may not submit; sub-agents report candidates only")
        if not flag:
            raise UnverifiedCandidate("no flag value")
        sha = _sha(flag)
        if not force and cid in self._solved:
            raise DuplicateSubmission(f"challenge {cid} already solved; not resubmitting")
        if not force and sha in self._tried_sha.get(cid, set()):
            raise DuplicateSubmission(f"flag already tried for challenge {cid} (sha {sha[:12]})")
        if self._scored.get(cid, 0) >= self.max_attempts:
            raise AttemptCapReached(
                f"challenge {cid} hit the attempt cap ({self.max_attempts})")
        return self._post_with_backoff(cid, flag, sha)

    def _post_with_backoff(self, cid, flag, sha):
        backoff = Backoff(sleep=self._sleep)
        last_err = None
        for _ in range(self.max_429_retries + 1):
            try:
                # cid is kept as-is (a CTFd client int-casts a numeric id itself; an
                # AI-challenge id like 'ai1' stays a string for non-CTFd targets).
                status, message = self.client.submit_flag(cid, flag)
            except RateLimited as e:
                last_err = e
                backoff.on_rate_limited()
                continue
            status = (status or "").lower()
            self._record(cid, sha, status, message)
            if status in SCORED_STATUSES:
                self._scored[cid] = self._scored.get(cid, 0) + 1
                self._tried_sha.setdefault(cid, set()).add(sha)
                if status in ("correct", "already_solved"):
                    self._solved.add(cid)
            return status, message
        # exhausted 429 retries
        self._record(cid, sha, "ratelimited", str(last_err))
        raise RateLimited(f"submit for {cid} still rate-limited after "
                          f"{self.max_429_retries} retries: {last_err}")

    # ---- append-only log (sha256 only) ----------------------------------
    def _record(self, cid, sha, status, message):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        row = {"ts": self._clock(), "cid": cid, "flag_sha256": sha,
               "status": status, "message": message, "role": self.role}
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
