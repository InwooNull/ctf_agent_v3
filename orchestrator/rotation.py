"""Phase CM3: operational discipline for CONTEST mode — the direct fix for the
WHITEHAT wipe-out (all effort poured into one problem, then a single token cut at
13:38 lost EVERYTHING with no resume).

Three guarantees, built by REUSING orchestrator.scheduler (EV/cost priority + global
cap) and orchestrator.stoploss (per-challenge budget + near-miss raise):

  1. No single challenge monopolises the budget. Every challenge first gets an initial
     triage slice; thereafter the scheduler's EV/cost priority steers extra budget to
     the ones showing progress, but a per-challenge StopLoss hard cap (strictly smaller
     than the global cap — enforced at construction) means no one challenge can ever
     swallow the whole session.

  2. A budget-exhausted-but-unsolved challenge is PRESERVED and ROTATED, not discarded:
     its StopLoss state + round counter + artifacts ride the checkpoint and it can be
     resumed in a later slice.

  3. EVERY challenge's progress survives a stop. After each slice the full per-challenge
     state is checkpointed to state.json AND an append-only events.jsonl line is written.
     On resume: solved/stopped are skipped, in-progress continue from preserved state,
     and no round is ever re-run (round counters are persisted and never replayed).

Bench mode does not use this runner; its blind path is unchanged. Governance files are
untouched (this reuses stoploss/scheduler, edits neither).
"""
import json
import os
import time
from pathlib import Path

from orchestrator import mode as mode_mod
from orchestrator.scheduler import Scheduler
from orchestrator.stoploss import StopLoss, STOP, RAISE_ONCE

# per-challenge lifecycle
PENDING = "pending"          # never sliced yet
IN_PROGRESS = "in_progress"  # sliced, preserved, resumable
SOLVED = "solved"            # terminal
STOPPED = "stopped"          # terminal (stop-loss gave up / hard cap)
TERMINAL = (SOLVED, STOPPED)

DEFAULT_GLOBAL_CAPS = {"experiments": 1000, "time_s": 1e9}
DEFAULT_CHALLENGE_CAPS = {"experiments": 12, "wall_s": 1200.0, "tokens": 0}


class MonopolyInvariantError(ValueError):
    """Raised when a per-challenge cap could let one challenge eat the whole budget."""


class RotationRunner:
    """Round-robin / priority rotation over a challenge set with preserved state.

    solver(cid, round_idx, info) -> {info_gain, verified_chain, candidate, wall_s, tokens}
        (same shape as orchestrator.competition's solver).
    submit(cid, candidate) -> bool   decides whether a candidate is an accepted solve.
        Default: a non-None candidate counts as solved. CM4 wires the real verifier/gate
        here; nothing in CM3 auto-submits to a live server.
    """

    def __init__(self, items, solver, store_dir, *, submit=None,
                 mode=mode_mod.CONTEST, global_caps=None, challenge_caps=None,
                 slice_rounds=2, no_progress_k=3, max_challenge_share=0.5, clock=time.time):
        self.items = [dict(it) for it in items]
        self.solver = solver
        self.submit = submit or (lambda cid, cand: cand is not None)
        self.mode = mode_mod.normalize(mode)
        self.store = Path(store_dir)
        self.store.mkdir(parents=True, exist_ok=True)
        self.global_caps = dict(global_caps or DEFAULT_GLOBAL_CAPS)
        self.challenge_caps = dict(challenge_caps or DEFAULT_CHALLENGE_CAPS)
        self.slice_rounds = int(slice_rounds)
        self.no_progress_k = int(no_progress_k)

        self._enforce_monopoly_invariant(max_challenge_share)

        self.scheduler = Scheduler(self.items, global_caps=self.global_caps)
        self.state_path = self.store / "state.json"
        self.events_path = self.store / "events.jsonl"
        # per-challenge preserved state
        self.ch = {it["id"]: {"id": it["id"], "status": PENDING, "round": 0,
                              "slices": 0, "has_chain": False, "solved": False,
                              "candidate": None, "stoploss": None}
                   for it in self.items}
        self._clock = clock
        self._resumed_skips = []
        self._load_state()

    # ---- the monopoly invariant (guarantee #1) --------------------------
    def _enforce_monopoly_invariant(self, max_share):
        """A per-challenge hard cap must be STRICTLY smaller than the global cap, so no
        single challenge can consume the entire budget. Checked for every shared key."""
        if len(self.items) <= 1:
            return
        for key in ("experiments", "time_s", "tokens"):
            gcap = self.global_caps.get(key) or (self.global_caps.get("wall_s")
                                                 if key == "time_s" else None)
            ccap = self.challenge_caps.get(key) or (self.challenge_caps.get("wall_s")
                                                    if key == "time_s" else None)
            if gcap and ccap and ccap > gcap * max_share:
                raise MonopolyInvariantError(
                    f"per-challenge {key} cap {ccap} exceeds {max_share:g}x global "
                    f"{gcap}; one challenge could monopolise the budget")

    # ---- events.jsonl (guarantee #3) ------------------------------------
    def _emit(self, cid, kind, **fields):
        rec = {"ts": round(self._clock(), 6), "cid": cid, "event": kind}
        rec.update(fields)
        with open(self.events_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return rec

    # ---- checkpoint / resume (guarantee #3) -----------------------------
    def _checkpoint(self):
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({
            "mode": self.mode,
            "challenges": self.ch,
            "scheduler_spent": self.scheduler.spent,
            "order": [it["id"] for it in self.items],
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.state_path)       # atomic: a crash never half-writes state

    def _load_state(self):
        if not self.state_path.is_file():
            return
        st = json.loads(self.state_path.read_text())
        for cid, cst in st.get("challenges", {}).items():
            if cid in self.ch:
                self.ch[cid].update(cst)
        self.scheduler.spent.update(st.get("scheduler_spent", {}))
        # re-establish terminal challenges in the scheduler so resume skips them
        for cid, cst in self.ch.items():
            if cst["status"] in TERMINAL:
                self.scheduler.mark_done(cid, cst["status"])

    # ---- selection ------------------------------------------------------
    def _next(self):
        if self.scheduler.global_exhausted():
            return None
        # guarantee #1 (fairness): give EVERY challenge its initial triage slice first,
        # in deterministic queue order, before anyone gets a second slice.
        pending = [it["id"] for it in self.items if self.ch[it["id"]]["status"] == PENDING]
        if pending:
            return pending[0]
        # thereafter: EV/cost priority among non-terminal challenges (progress -> more)
        live = [it["id"] for it in self.items if self.ch[it["id"]]["status"] not in TERMINAL]
        if not live:
            return None
        return max(live, key=lambda c: (self.scheduler.priority(c),
                                        -self.scheduler.order.index(c)))

    # ---- one slice ------------------------------------------------------
    def _run_slice(self, cid):
        st = self.ch[cid]
        sl = (StopLoss.from_dict(st["stoploss"]) if st["stoploss"]
              else StopLoss(caps=dict(self.challenge_caps), no_progress_k=self.no_progress_k))
        st["status"] = IN_PROGRESS
        self._emit(cid, "slice_start", slice=st["slices"] + 1, round=st["round"],
                   spent=dict(sl.spent))
        slice_gain = 0.0
        for _ in range(self.slice_rounds):
            if sl.over_budget():                     # per-challenge hard cap (anti-monopoly)
                self._emit(cid, "stoploss", reason=f"hard_cap:{sl.over_budget()}",
                           spent=dict(sl.spent))
                return self._terminate(cid, STOPPED, sl)
            r = self.solver(cid, st["round"], {"has_chain": st["has_chain"]}) or {}
            st["round"] += 1
            gain = float(r.get("info_gain", 0) or 0)
            slice_gain += gain
            sl.record_round(info_gain=gain, experiments=1,
                            wall_s=float(r.get("wall_s", 0) or 0), tokens=int(r.get("tokens", 0) or 0))
            self.scheduler.record_spend(experiments=1, time_s=float(r.get("wall_s", 0) or 0))
            st["has_chain"] = st["has_chain"] or bool(r.get("verified_chain"))
            self._emit(cid, "round", idx=st["round"], info_gain=gain, spent=dict(sl.spent))
            cand = r.get("candidate")
            if cand is not None:
                ok = bool(self.submit(cid, cand))
                self._emit(cid, "candidate", round=st["round"], accepted=ok)
                if ok:
                    st["candidate"] = getattr(cand, "value", cand)
                    return self._terminate(cid, SOLVED, sl)
            dec = sl.decide(has_verified_chain=st["has_chain"])
            if dec == RAISE_ONCE:
                self._emit(cid, "raise_once", caps=dict(sl.caps))
                continue
            if dec == STOP:
                self._emit(cid, "stoploss", reason="stall_or_budget", spent=dict(sl.spent))
                return self._terminate(cid, STOPPED, sl)
        # slice quantum reached, not terminal -> PRESERVE + ROTATE (guarantee #2)
        st["slices"] += 1
        st["stoploss"] = sl.to_dict()
        st["status"] = IN_PROGRESS
        self.scheduler.update_difficulty(cid, "easier" if slice_gain > 0 else "harder")
        self._emit(cid, "rotate", preserved=True, round=st["round"],
                   slices=st["slices"], spent=dict(sl.spent))

    def _terminate(self, cid, status, sl):
        st = self.ch[cid]
        st["status"] = status
        st["solved"] = (status == SOLVED)
        st["stoploss"] = sl.to_dict()
        self.scheduler.mark_done(cid, status)
        self.scheduler.update_difficulty(cid, "easier" if status == SOLVED else "harder")
        self._emit(cid, status, round=st["round"])

    # ---- the run --------------------------------------------------------
    def run(self, max_slices=None):
        # record which challenges are resumed/skipped (for the resume log + tests)
        for cid, st in self.ch.items():
            if st["status"] in TERMINAL:
                self._resumed_skips.append(cid)
                self._emit(cid, "resume_skip", status=st["status"])
            elif st["status"] == IN_PROGRESS:
                self._emit(cid, "resume_continue", round=st["round"], slices=st["slices"])

        slices_run = 0
        while True:
            g = self.scheduler.global_exhausted()
            if g:
                self._emit("run", "global_budget_spent", key=g)
                break
            cid = self._next()
            if cid is None:
                self._emit("run", "queue_drained")
                break
            self._run_slice(cid)
            slices_run += 1
            self._checkpoint()                       # ALL challenges' progress preserved
            if max_slices is not None and slices_run >= max_slices:
                self._emit("run", "interrupted", slices_run=slices_run)
                break

        self._checkpoint()
        return self.summary()

    def summary(self):
        by_status = {}
        for st in self.ch.values():
            by_status.setdefault(st["status"], []).append(st["id"])
        return {
            "mode": self.mode,
            "status": {cid: st["status"] for cid, st in self.ch.items()},
            "solved": [cid for cid, st in self.ch.items() if st["solved"]],
            "by_status": by_status,
            "scheduler_spent": dict(self.scheduler.spent),
            "resumed_skips": list(self._resumed_skips),
            "rounds": {cid: st["round"] for cid, st in self.ch.items()},
        }
