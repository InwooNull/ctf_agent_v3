"""GrowthLoop — the autonomous growth loop skeleton (Phase 44a).

One cycle = run -> diagnose -> improve -> regress-gate -> commit/rollback. The loop is a
PURE ORCHESTRATOR: it never implements a solver or a runner of its own and never reads a
scorer key. It is handed, by dependency injection, the pieces that already exist:

  run_batch(dev_batch) -> BatchResult
      Calls an EXISTING blind runner (orchestrator.competition / eval.p*_runner) on the
      dev pool and returns per-cid outcomes + the store/pNN-style report dict. The loop
      does NOT create a new runner (Phase-44 rule). In tests this is a deterministic
      fake so a cycle costs zero tokens.
  diagnoser (44b), improver (44c), regressor (44c)
      Optional. When absent the loop runs with empty diagnosis/improvement — exactly the
      44a acceptance (an end-to-end no-op cycle with checkpointing).

Autonomy boundary (enforced from 44b on; declared here so the skeleton already carries
it): only AUTO buckets may change skill-pack/routing/experience/budget; tool or harness
or governance changes are HUMAN-GATE (logged, never auto-applied); human-grade failures
are SKIPped. The loop touches dev only; holdout is the regressor's blind regression set.
"""
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, List, Optional

from growth.state import GrowthState, STEPS


# --- data carried between the pieces -----------------------------------------
@dataclass
class RunOutcome:
    cid: str
    outcome: str                 # SOLVED | GIVE_UP | FLAG_WITHOUT_SOLUTION | NO_TERMINAL | BLOCKED
    solved: bool
    category: str = ""
    difficulty: str = ""
    run_dir: str = ""            # where the blind runner wrote this run (for the diagnoser to read)
    trace_ref: str = ""          # the agent's own transcript (diagnosis reads ONLY this + verified flag)
    signals: dict = field(default_factory=dict)  # trace signals the diagnoser classifies on (44b)


@dataclass
class BatchResult:
    runs: List[RunOutcome]
    report: dict = field(default_factory=dict)   # the store/pNN report.json dict (aggregate)


@dataclass
class CycleReport:
    cycle_id: str
    solved: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    diagnoses: List[dict] = field(default_factory=list)
    improvements_applied: List[dict] = field(default_factory=list)
    improvements_rolled_back: List[dict] = field(default_factory=list)
    regression_delta: float = 0.0
    stop_reason: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class GrowthLoop:
    def __init__(self, store_root, run_batch: Callable[[list], BatchResult],
                 diagnoser=None, improver=None, regressor=None,
                 max_cycles: Optional[int] = None, no_progress_k: int = 3,
                 budget_caps: Optional[dict] = None, requests_path=None):
        self.run_dir = Path(store_root)
        self.run_batch = run_batch
        self.diagnoser = diagnoser
        self.improver = improver
        self.regressor = regressor
        self.max_cycles = max_cycles
        self.no_progress_k = no_progress_k
        self.budget_caps = budget_caps or {}
        # growth/requests.md (HUMAN-GATE/SKIP/cyber log). Default: alongside the run dir.
        self.requests_path = Path(requests_path) if requests_path else (self.run_dir / "requests.md")
        self.state = GrowthState(self.run_dir)

    # ---- one cycle ---------------------------------------------------------
    def cycle(self, dev_batch, cycle_id=None) -> CycleReport:
        """Run one full cycle on the dev batch. Resume-safe: each step is checkpointed,
        so a crash re-enters at the first step whose result is not yet durable."""
        resume = self.state.resume_cycle_id()
        if cycle_id is None:
            cycle_id = resume or f"c{len(self.state.completed_cycle_ids()) + 1}"
        self.state.begin_cycle(cycle_id)
        p = self.state.partial()

        # 1) RUN (reuse an existing blind runner via the injected callable)
        if self.state.step_done("run"):
            solved, failed_cids = p["solved"], p["failed"]
            failed_runs = [RunOutcome(**r) for r in p.get("failed_runs", [])]
            batch_runs = [RunOutcome(**r) for r in p.get("all_runs", p.get("failed_runs", []))]
        else:
            batch = self.run_batch(dev_batch)
            batch_runs = list(batch.runs)
            failed_runs = [r for r in batch_runs if not r.solved]
            solved = [r.cid for r in batch_runs if r.solved]
            failed_cids = [r.cid for r in failed_runs]
            self.state.record_step("run", {
                "solved": solved, "failed": failed_cids,
                "failed_runs": [asdict(r) for r in failed_runs],
                "all_runs": [asdict(r) for r in batch_runs]})

        # 2) DIAGNOSE (44b; empty when no diagnoser). Non-AUTO/SKIP buckets are logged to
        # growth/requests.md here (never auto-applied); this accrues across cycles.
        if self.state.step_done("diagnose"):
            diagnoses = self.state.partial()["diagnoses"]
        else:
            diagnoses = self.diagnoser.diagnose(failed_runs) if self.diagnoser else []
            if self.diagnoser and self.requests_path and diagnoses:
                from growth.diagnoser import write_requests
                write_requests(diagnoses, self.requests_path)
            self.state.record_step("diagnose", {"diagnoses": diagnoses})

        # 3) IMPROVE + GATE (44c): the improver applies AUTO improvements ONE AT A TIME,
        # each gated (dev-target flip AND holdout no-drop) and committed or atomically
        # rolled back BEFORE the next — so the regress decision is owned per-change here,
        # not batched. Empty when no improver (44a behaviour).
        if self.state.step_done("improve"):
            pp = self.state.partial()
            applied = pp["improvements_applied"]
            rolled_back = pp["improvements_rolled_back"]
            regression_delta = pp["regression_delta"]
        else:
            if self.improver:
                snap_root = self.run_dir / "snapshots" / cycle_id
                ledger = self.state.partial().get("improve_ledger",
                                                  {"started": {}, "decided": [], "initial_score": None})
                def _persist(l, _st=self.state):
                    _st.update_partial({"improve_ledger": l})
                applied, rolled_back, regression_delta = self.improver.run_resumable(
                    diagnoses, batch_runs, snap_root=snap_root, ledger=ledger, persist=_persist)
            else:
                applied, rolled_back, regression_delta = [], [], 0.0
            self.state.record_step("improve", {
                "improvements_applied": applied,
                "improvements_rolled_back": rolled_back,
                "regression_delta": regression_delta})

        # 4) REGRESS record (gating already happened per-change inside the improver).
        if not self.state.step_done("regress"):
            self.state.record_step("regress", {})

        # 5) COMMIT (assemble the report; persist; clear in_progress)
        report = CycleReport(
            cycle_id=cycle_id, solved=solved, failed=failed_cids, diagnoses=diagnoses,
            improvements_applied=applied, improvements_rolled_back=rolled_back,
            regression_delta=regression_delta, stop_reason=None)
        self.state.record_step("commit", {})
        self.state.complete_cycle(report.to_dict())
        return report

    # ---- many cycles until a stop condition (44d uses this) ----------------
    def run(self, dev_batch, max_cycles=None) -> List[CycleReport]:
        max_cycles = max_cycles if max_cycles is not None else self.max_cycles
        reports: List[CycleReport] = []
        no_progress = 0
        while True:
            stop = self._stop_reason(len(self.state.completed_cycle_ids()), no_progress, max_cycles)
            if stop:
                # record a terminal zero-work report so the stop is visible in the trail
                if reports:
                    reports[-1].stop_reason = stop
                break
            rep = self.cycle(dev_batch)
            # convergence is about the loop still IMPROVING itself: progress = a net
            # adoption this cycle. Constant dev solves (same fixed batch) are not progress.
            made_progress = len(rep.improvements_applied) > 0
            no_progress = 0 if made_progress else no_progress + 1
            reports.append(rep)
            stop = self._stop_reason(len(self.state.completed_cycle_ids()), no_progress, max_cycles)
            if stop:
                rep.stop_reason = stop
                self._rewrite_last(rep)
                break
        return reports

    def _stop_reason(self, n_done, no_progress, max_cycles):
        if max_cycles is not None and n_done >= max_cycles:
            return "max_cycles"
        if no_progress >= self.no_progress_k:
            return "converged_no_progress"
        cap = self.budget_caps.get("max_cycles")
        if cap is not None and n_done >= cap:
            return "budget_cap"
        return None

    def _rewrite_last(self, rep):
        """Persist an updated stop_reason onto the last stored cycle report."""
        if self.state.data["cycles"]:
            self.state.data["cycles"][-1] = rep.to_dict()
            self.state.save()
