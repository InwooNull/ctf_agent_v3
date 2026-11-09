"""Integrated orchestrator run — the whole agent, end to end, on a mock competition.

This is where the tested parts finally run together as ONE agent (the v2 failure was
"the orchestration never ran together"): connector fetch -> classify/route -> the
flags-per-hour Scheduler -> per-challenge StopLoss round loop -> candidate -> triage
first-pass/decoy screen -> the reproduce-before-submit SubmitGate -> submit. All four
Phase-29 policies are wired in here; the Phase-0 Supervisor (a single-queue mock engine)
is intentionally left untouched so its tests stay byte-identical.

Deterministic and offline: the "solver" is a scripted per-role policy (NOT an LLM), the
platform is connector.mock_ctfd, and every flag lives only in the mock server + the
scripted fixture. No live access, no performance claim — this proves the pipeline wiring.

Resume-safe: completed challenges are checkpointed to store/<run>/state.json, and the
SubmitGate's own append-only log makes submission idempotent across a stop/resume.
"""
import json
from pathlib import Path

from orchestrator import mode as mode_mod
from orchestrator.classifier import classify
from orchestrator.router import route
from orchestrator.scheduler import Scheduler
from orchestrator.stoploss import StopLoss, STOP, RAISE_ONCE
from orchestrator import triage
from connector.submit_gate import (
    SubmitGate, DecoyRejected, ReproductionFailed, UnverifiedCandidate,
    DuplicateSubmission, AttemptCapReached,
)
from connector.ctfd_client import RateLimited
from schemas.records import Candidate

MAX_ROUNDS = 40  # hard per-challenge safety bound (StopLoss normally stops sooner)


class Competition:
    """Drive one mock competition end to end.

    solver: callable (cid, round_idx, info) -> dict with keys
        info_gain (float), verified_chain (bool), candidate (Candidate|None).
    reproducer: callable (cid, candidate) -> {"ok": bool, "flag": str} (the clean
        history-free re-derivation the SubmitGate requires before submitting).
    script: cid -> {score, difficulty, est_cost} (scheduler inputs).
    """

    def __init__(self, client, arena_dir, store_dir, solver, reproducer, script,
                 global_caps=None, challenge_caps=None, no_progress_k=3,
                 mode=mode_mod.DEFAULT):
        self.client = client
        # CM1: which mode this run is. Default "contest"; "bench" is the existing
        # blind path. CM1 only RECORDS it (profile surfaced, state/return carry it);
        # the behavioural branches (network/discipline/evidence) land in CM2-CM4.
        self.mode = mode_mod.normalize(mode)
        self.profile = mode_mod.profile(self.mode)
        self.arena = Path(arena_dir)
        self.store = Path(store_dir)
        self.store.mkdir(parents=True, exist_ok=True)
        self.solver = solver
        self.script = script
        self.global_caps = dict(global_caps or {"experiments": 1000, "time_s": 1e9})
        self.challenge_caps = dict(challenge_caps or {"experiments": 3})
        self.no_progress_k = no_progress_k
        self.gate = SubmitGate.for_orchestrator(
            client, log_path=self.store / "submissions.jsonl",
            decoy_check=triage.is_decoy, reproducer=reproducer)
        self.state_path = self.store / "state.json"
        self.trace = []           # per-challenge records
        self.events = []          # flat policy-firing log (strings)
        self._done = {}           # cid -> outcome
        self._load_state()

    # ---- checkpoint -----------------------------------------------------
    def _load_state(self):
        if self.state_path.is_file():
            st = json.loads(self.state_path.read_text())
            self._done = st.get("done", {})
            self.trace = st.get("trace", [])
            self.events = st.get("events", [])

    def _save_state(self, scheduler):
        self.state_path.write_text(json.dumps({
            "mode": self.mode,
            "done": self._done, "trace": self.trace, "events": self.events,
            "spent": scheduler.spent,
        }, indent=1), encoding="utf-8")

    def _ev(self, cid, msg):
        self.events.append(f"[{cid}] {msg}")

    @staticmethod
    def _submit_id(cid):
        """The id the SubmitGate/client submit against: the numeric CTFd id behind a
        'live_<n>' cid (the live client int-casts it), else the cid unchanged."""
        s = str(cid)
        if s.startswith("live_") and s[len("live_"):].isdigit():
            return int(s[len("live_"):])
        return cid

    # ---- fetch + schedule ----------------------------------------------
    def _fetch_and_schedule(self):
        from connector import fetch
        results, manifest = fetch.fetch_all(
            self.client, arena=self.arena, store=self.store / "live")
        items, meta = [], {}
        for r in results:
            cid = r["cid"]
            chal_dir = self.arena / cid
            chal = json.loads((chal_dir / "challenge.json").read_text())
            cat = classify(chal)
            lane = route(cat)
            sc = self.script.get(cid, {})
            items.append({"id": cid, "score": sc.get("score", r.get("value") or 100),
                          "difficulty": sc.get("difficulty", "med"),
                          "est_cost": sc.get("est_cost", 1.0)})
            meta[cid] = {"category": cat, "lane": lane, "dir": chal_dir}
        return Scheduler(items, global_caps=self.global_caps), meta

    # ---- submission attempt --------------------------------------------
    def _try_submit(self, cid, candidate):
        """Return (tag, status). tag in {ok, decoy, repro_fail, unverified, dup, cap,
        ratelimited, incorrect}. Never raises past the governed exceptions."""
        try:
            status, _ = self.gate.submit_candidate(self._submit_id(cid), candidate)
            return ("ok" if status in ("correct", "already_solved") else "incorrect", status)
        except DecoyRejected:
            return "decoy", None
        except ReproductionFailed:
            return "repro_fail", None
        except UnverifiedCandidate:
            return "unverified", None
        except DuplicateSubmission:
            return "dup", None
        except AttemptCapReached:
            return "cap", None
        except RateLimited:
            return "ratelimited", None

    # ---- per-challenge solve -------------------------------------------
    def _solve_challenge(self, cid, chal_dir):
        stop = StopLoss(caps=dict(self.challenge_caps), no_progress_k=self.no_progress_k)
        has_chain = False
        rounds = 0
        outcome = "unsolved"

        # 1) cheap first pass: exposed flags, with the decoy screen on the submit path
        for hit in triage.first_pass(chal_dir):
            cand = Candidate(value=hit["value"], confidence=0.9,
                             evidence_refs=[f"first_pass:{hit['path']}"], status="VERIFIED")
            tag, _ = self._try_submit(cid, cand)
            if tag == "ok":
                self._ev(cid, f"first_pass solved via {hit['path']}")
                return "solved", rounds
            if tag == "decoy":
                self._ev(cid, f"first_pass hit {hit['value']!r} rejected as decoy")

        # 2) scripted solve under the per-challenge stop-loss
        while rounds < MAX_ROUNDS:
            r = self.solver(cid, rounds, {"has_chain": has_chain})
            rounds += 1
            stop.record_round(info_gain=r.get("info_gain", 0), experiments=1)
            has_chain = has_chain or bool(r.get("verified_chain"))
            cand = r.get("candidate")
            if cand is not None:
                tag, _ = self._try_submit(cid, cand)
                if tag == "ok":
                    self._ev(cid, f"solved at round {rounds}")
                    return "solved", rounds
                self._ev(cid, f"candidate at round {rounds} rejected: {tag}")
            decision = stop.decide(has_verified_chain=has_chain)
            if decision == RAISE_ONCE:
                self._ev(cid, f"stop-loss near-miss: budget raised once (verified chain held)")
                continue
            if decision == STOP:
                self._ev(cid, f"stop-loss: no progress, giving up after {rounds} rounds")
                return "stopped", rounds
        return "stopped", rounds

    # ---- the run --------------------------------------------------------
    def run(self, max_challenges=None):
        scheduler, meta = self._fetch_and_schedule()
        for cid, outcome in self._done.items():
            scheduler.mark_done(cid, outcome)   # resume: skip finished challenges

        processed = 0
        while True:
            if max_challenges is not None and processed >= max_challenges:
                self._ev("run", "interrupted (max_challenges reached)")
                break
            cid = scheduler.next()
            if cid is None:
                g = scheduler.global_exhausted()
                self._ev("run", f"queue drained" if not g else f"global budget spent: {g}")
                break
            m = meta[cid]
            self._ev(cid, f"dispatch category={m['category']} lane={m['lane']} "
                          f"priority={scheduler.priority(cid):.2f}")
            outcome, rounds = self._solve_challenge(cid, m["dir"])
            scheduler.mark_done(cid, outcome)
            scheduler.record_spend(experiments=rounds)
            scheduler.update_difficulty(cid, "easier" if outcome == "solved" else "harder")
            self._done[cid] = outcome
            self.trace.append({"cid": cid, "category": m["category"], "lane": m["lane"],
                               "outcome": outcome, "rounds": rounds})
            processed += 1
            self._save_state(scheduler)

        self._save_state(scheduler)
        return {"mode": self.mode, "trace": self.trace, "events": self.events,
                "done": dict(self._done), "spent": scheduler.spent,
                "remaining": scheduler.remaining()}
