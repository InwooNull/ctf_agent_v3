"""Checkpoint/resume for the autonomous growth loop (Phase 44a).

Reuses the existing checkpoint discipline (atomic state.json rewrite; a completed step
is durable before the next begins) so a growth run survives a crash/power-loss exactly
like orchestrator.Supervisor does. ADDITIVE: it writes only its own
`growth_state.json` under the growth run dir and touches nothing else.

The state tracks completed cycles (their CycleReport dicts) plus one optional
`in_progress` record so a cycle interrupted mid-way (after `run`, before `regress`, …)
resumes from the last durable step instead of re-running the batch.
"""
from pathlib import Path

from orchestrator.supervisor import _atomic_write_json  # reuse the exact atomic writer

SCHEMA = "growth-state-v1"
# the ordered steps of a single cycle; resume picks up at the first not-yet-done step.
STEPS = ("run", "diagnose", "improve", "regress", "commit")


class GrowthState:
    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / "growth_state.json"
        if self.path.is_file():
            import json
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.data = {"schema": SCHEMA, "cycles": [], "in_progress": None}
            self.save()

    # ---- persistence -------------------------------------------------------
    def save(self):
        _atomic_write_json(self.path, self.data)

    # ---- cycle lifecycle ---------------------------------------------------
    def completed_cycle_ids(self):
        return [c["cycle_id"] for c in self.data["cycles"]]

    def cycles(self):
        return list(self.data["cycles"])

    def last_report(self):
        return self.data["cycles"][-1] if self.data["cycles"] else None

    def begin_cycle(self, cycle_id):
        """Open (or re-open on resume) a cycle. Returns the in_progress record."""
        ip = self.data.get("in_progress")
        if ip and ip["cycle_id"] == cycle_id:
            return ip                      # resuming the same cycle: keep its partial
        self.data["in_progress"] = {"cycle_id": cycle_id, "done_steps": [], "partial": {}}
        self.save()
        return self.data["in_progress"]

    def record_step(self, step, partial):
        """Mark `step` durably done, merging any partial result it produced."""
        ip = self.data["in_progress"]
        if ip is None:
            raise RuntimeError("record_step with no in_progress cycle")
        if step not in ip["done_steps"]:
            ip["done_steps"].append(step)
        ip["partial"].update(partial)
        self.save()

    def update_partial(self, partial):
        """Merge into the in-progress partial and persist WITHOUT marking a step done.
        Used for sub-step checkpoints inside a long step (e.g. per-improvement progress
        during `improve`), so a crash resumes mid-step instead of redoing it."""
        ip = self.data.get("in_progress")
        if ip is None:
            raise RuntimeError("update_partial with no in_progress cycle")
        ip["partial"].update(partial)
        self.save()

    def step_done(self, step):
        ip = self.data.get("in_progress")
        return bool(ip and step in ip["done_steps"])

    def partial(self):
        ip = self.data.get("in_progress")
        return dict(ip["partial"]) if ip else {}

    def resume_cycle_id(self):
        ip = self.data.get("in_progress")
        return ip["cycle_id"] if ip else None

    def complete_cycle(self, report):
        """Append the finished CycleReport dict and clear in_progress."""
        self.data["cycles"].append(report)
        self.data["in_progress"] = None
        self.save()
