"""Supervisor: queue -> classify -> route -> dispatch(mock) with checkpoint/resume and budget gating.

The run is a state machine driven by Checkpoint.next_action:
  {"kind": "dispatch",   "queue_index": i}
  {"kind": "experiment", "queue_index": i, "hyp_index": h, "exp_index": e}
  {"kind": "done"}
After every action the cursor is normalized (_advance) so next_action always points
at real work, and state.json is rewritten atomically. Budget is checked *before* each
dispatch/experiment; when exhausted the run stops with status "aborted".
"""
import json
import os
import time
from pathlib import Path

from orchestrator.classifier import classify
from orchestrator.router import route
from schemas.records import Candidate, Checkpoint, Experiment
from solver.experiment_log import ExperimentLog, enforce_judgment_separation
from solver.mock_solver import MockSolver

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.json"


def load_settings(path=None):
    with open(path or DEFAULT_SETTINGS_PATH, encoding="utf-8") as f:
        return json.load(f)


def _atomic_write_json(path, obj):
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class Supervisor:
    def __init__(self, run_id, settings=None, store_root=None, clock=None, solver_factory=MockSolver):
        self.settings = settings if settings is not None else load_settings()
        if self.settings.get("concurrency", 1) != 1:
            raise ValueError("Phase 0 supports concurrency=1 only")
        root = Path(store_root) if store_root else PROJECT_ROOT / self.settings["paths"]["runs_dir"]
        self.run_id = run_id
        self.run_dir = root / run_id
        self.state_path = self.run_dir / "state.json"
        self.clock = clock or time.monotonic
        self.solver_factory = solver_factory
        self.state = None
        self.cp = None
        self.log = None
        self.executions = 0  # actual (non-cached) executions in this session
        self._solver = None
        self._solver_cid = None
        self._time_base = 0.0
        self._t0 = 0.0

    # ---- lifecycle -------------------------------------------------------

    def start(self, challenges):
        if self.state_path.exists():
            raise FileExistsError(f"run already exists: {self.run_dir}")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.state = {
            "run_id": self.run_id,
            "seed": self.settings["seed"],
            "budget": dict(self.settings["budget"]),
            "default_timeout_s": self.settings.get("defaults", {}).get("experiment_timeout_s", 30),
            "queue": list(challenges),
            "status": "running",
            "current": None,
            "results": {},
        }
        first = {"kind": "dispatch", "queue_index": 0} if challenges else {"kind": "done"}
        self.cp = Checkpoint(self.run_id, None, [], {"time_s": 0.0, "rounds": 0, "attempts": 0}, first, {})
        self.log = ExperimentLog(self.run_dir)
        self._begin_session()
        self.log.append_event("run_started", queue=[c["id"] for c in challenges])
        self._save("run_started")
        return self

    @classmethod
    def resume(cls, run_id, **kwargs):
        sup = cls(run_id, **kwargs)
        with open(sup.state_path, encoding="utf-8") as f:
            sup.state = json.load(f)
        sup.cp = Checkpoint.from_dict(sup.state["checkpoint"])
        sup.log = ExperimentLog(sup.run_dir)
        # Idempotent resume: discard any log tail appended after the last committed
        # checkpoint (crash between append_event and _save).
        sp = sup.cp.safe_point
        sup.log.reconcile(sup.state.get("last_committed_seq", sp.get("event_seq", 0)),
                          sp.get("command_seq", 0))
        sup._begin_session()
        sup.log.append_event("run_resumed", next_action=sup.cp.next_action, safe_point=sup.cp.safe_point)
        return sup

    def run(self, stop_after_steps=None):
        """Run until done, budget exhaustion, or stop_after_steps actions. Returns final status."""
        steps = 0
        while True:
            action = self.cp.next_action
            if action["kind"] == "done":
                self.state["status"] = "completed"
                self.log.append_event("run_completed", budget_spent=self._spent())
                self._save("completed")
                return "completed"

            blocked = self._budget_block(action["kind"])
            if blocked:
                return self._abort(blocked)

            self.state["status"] = "running"
            if action["kind"] == "dispatch":
                self._dispatch(action)
            elif action["kind"] == "experiment":
                self._experiment(action)
            else:
                raise ValueError(f"unknown action {action!r}")
            self._save(f"after_{action['kind']}")

            steps += 1
            if stop_after_steps is not None and steps >= stop_after_steps and self.cp.next_action["kind"] != "done":
                self.state["status"] = "interrupted"
                self.log.append_event("run_interrupted", next_action=self.cp.next_action)
                self._save("interrupted")
                return "interrupted"

    # ---- budget ----------------------------------------------------------

    def _begin_session(self):
        self._time_base = float(self.cp.budget_spent["time_s"])
        self._t0 = self.clock()

    def _spent(self):
        spent = dict(self.cp.budget_spent)
        spent["time_s"] = self._time_base + (self.clock() - self._t0)
        return spent

    def _budget_block(self, kind):
        spent, budget = self._spent(), self.state["budget"]
        if spent["time_s"] >= budget["time_s"]:
            return "time_s"
        if kind == "dispatch" and spent["rounds"] >= budget["max_rounds"]:
            return "max_rounds"
        if kind == "experiment" and spent["attempts"] >= budget["max_attempts"]:
            return "max_attempts"
        return None

    def _abort(self, reason):
        self.state["status"] = "aborted"
        self.cp.next_action = {**self.cp.next_action, "blocked_by": reason}
        self.log.append_event("budget_exhausted", blocked_by=reason, blocked_action=self.cp.next_action,
                              budget=self.state["budget"], budget_spent=self._spent())
        self._save("aborted")
        return "aborted"

    # ---- actions ---------------------------------------------------------

    def _solver_for(self, challenge):
        if self._solver_cid != challenge["id"]:
            self._solver = self.solver_factory(challenge.get("scenario", {}), self.state["seed"], self.clock)
            self._solver_cid = challenge["id"]
        return self._solver

    def _dispatch(self, action):
        qi = action["queue_index"]
        challenge = self.state["queue"][qi]
        category = classify(challenge)
        lane = route(category)
        self.cp.budget_spent["rounds"] += 1
        hypotheses = self._solver_for(challenge).propose_hypotheses(challenge["id"])
        self.cp.challenge_id = challenge["id"]
        self.cp.active_hypotheses = hypotheses
        self.state["current"] = {"challenge_id": challenge["id"], "category": category, "lane": lane,
                                 "experiments": [], "candidates": []}
        self.log.append_event("dispatched", challenge_id=challenge["id"], category=category, lane=lane,
                              hypotheses=[h.id for h in hypotheses])
        self.cp.next_action = {"kind": "experiment", "queue_index": qi, "hyp_index": 0, "exp_index": 0}
        self._advance()

    def _experiment(self, action):
        qi, hi, ei = action["queue_index"], action["hyp_index"], action["exp_index"]
        challenge = self.state["queue"][qi]
        solver = self._solver_for(challenge)
        hyp = self.cp.active_hypotheses[hi]
        hyp.status = "testing"
        spec = solver.experiment_spec(hi, ei)
        spec.setdefault("timeout", self.state["default_timeout_s"])
        exp_id = f"{hyp.id}-E{ei}"

        result = self.log.run(exp_id, spec, solver.execute)
        if not result["cached"]:
            self.cp.budget_spent["attempts"] += 1
            self.executions += 1
        judgment = enforce_judgment_separation(
            result["execution_status"], solver.judge(hi, ei, result["observation"]))
        exp = Experiment(
            id=exp_id, hypothesis_id=hyp.id, tool=spec["tool"], argv=spec["argv"], env=spec["env"],
            cwd=spec["cwd"], timeout=spec["timeout"], dedup_key=result["dedup_key"],
            execution_status=result["execution_status"], observation_ref=result["observation_ref"],
            hypothesis_judgment=judgment, evidence_refs=[result["observation_ref"]],
            nondeterministic=spec["nondeterministic"],
        )
        current = self.state["current"]
        current["experiments"].append(exp.to_dict())
        hyp.experiment_ids.append(exp_id)
        self.log.append_event("experiment_judged", experiment_id=exp_id, hypothesis_id=hyp.id,
                              execution_status=exp.execution_status, hypothesis_judgment=judgment,
                              cached=result["cached"])

        self.cp.next_action = {"kind": "experiment", "queue_index": qi, "hyp_index": hi, "exp_index": ei + 1}
        if judgment == "refute":
            hyp.status = "refuted"
        elif judgment == "support":
            hyp.status = "supported"
            flag = solver.candidate_flag(hi)
            if flag is not None:
                cand = Candidate(value=flag, confidence=0.5, evidence_refs=[exp_id, result["observation_ref"]])
                cand.status = solver.verify(cand.value)
                current["candidates"].append(cand.to_dict())
                self.log.append_event("candidate", value=cand.value, status=cand.status, evidence_refs=cand.evidence_refs)
                if cand.status == "VERIFIED":
                    self._finish_challenge("solved")
                    return
        self._advance()

    def _advance(self):
        """Move the experiment cursor past decided/exhausted hypotheses."""
        while self.cp.next_action["kind"] == "experiment":
            na = self.cp.next_action
            qi, hi, ei = na["queue_index"], na["hyp_index"], na["exp_index"]
            hyps = self.cp.active_hypotheses
            if hi >= len(hyps):
                self._finish_challenge("unsolved")
                return
            hyp = hyps[hi]
            if hyp.status in ("supported", "refuted") or ei >= self._solver_for(self.state["queue"][qi]).num_experiments(hi):
                if hyp.status in ("proposed", "testing"):
                    hyp.status = "held"
                self.cp.next_action = {"kind": "experiment", "queue_index": qi, "hyp_index": hi + 1, "exp_index": 0}
                continue
            return

    def _finish_challenge(self, outcome):
        current = self.state["current"]
        qi = self.cp.next_action["queue_index"]
        self.state["results"][current["challenge_id"]] = {
            "outcome": outcome,
            "category": current["category"],
            "lane": current["lane"],
            "hypotheses": [h.to_dict() for h in self.cp.active_hypotheses],
            "experiments": current["experiments"],
            "candidates": current["candidates"],
        }
        self.log.append_event("challenge_finished", challenge_id=current["challenge_id"], outcome=outcome)
        self.state["current"] = None
        self.cp.challenge_id = None
        self.cp.active_hypotheses = []
        nxt = qi + 1
        self.cp.next_action = {"kind": "dispatch", "queue_index": nxt} if nxt < len(self.state["queue"]) else {"kind": "done"}

    # ---- persistence -----------------------------------------------------

    def _save(self, label):
        self.cp.budget_spent = self._spent()
        self.cp.safe_point = {"label": label, "event_seq": self.log.event_seq, "command_seq": self.log.command_seq}
        self.state["checkpoint"] = self.cp.to_dict()
        # last_committed_seq marks the newest event durably reflected in this snapshot;
        # anything in events.jsonl beyond it on resume is an uncommitted crash tail.
        self.state["last_committed_seq"] = self.log.event_seq
        _atomic_write_json(self.state_path, self.state)
