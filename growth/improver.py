"""Improver — applies AUTO-bucket improvements ONE AT A TIME, each gated and committed or
atomically rolled back before the next is tried (Phase 44c).

Sequential discipline (requirement 1): never batch several changes behind one gate. For
each improvement: snapshot the surface -> mutate -> gate -> if adopted, keep and advance
the baseline; else restore the snapshot (hash-verified) and record a rollback. This
attributes any regression to the exact change that caused it and bounds the blast radius
to one change.

Experience hygiene: experience promotion draws ONLY from `promotable_successes` (Phase
44b), so an FWS false-positive is never promoted as a success memory. A bucket that is
not AUTO is never turned into an improvement here — it was already logged for a human by
the diagnoser.

Blindness: the improver reads DEV outcomes only to decide what to try; it never reads a
holdout answer. The holdout is touched exclusively by the Regressor's blind grader.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from growth.diagnoser import is_auto, promotable_successes
from growth.surface import Surface


@dataclass
class Improvement:
    id: str
    kind: str                       # knowledge_gap | experience_gap | budget | approach
    targeted_cids: list             # the previous dev failures this change must flip
    mutate: Callable                # mutate(surface) -> None, edits a managed file in place
    describe: str = ""
    within_cap: bool = True         # budget changes: False if the proposal exceeds the cap


class Improver:
    def __init__(self, surface: Surface, regressor, drafter: Optional[Callable] = None):
        """surface: the AUTO self-modify files. regressor: the dual-condition gate.
        drafter(diagnosis, batch_runs) -> Improvement|None : builds the concrete edit for a
        diagnosis (the agent's own Claude in production; injected/omitted in tests)."""
        self.surface = surface
        self.regressor = regressor
        self.drafter = drafter

    # ---- build concrete improvements from AUTO diagnoses -------------------
    def build(self, diagnoses, batch_runs) -> List[Improvement]:
        successes = promotable_successes(batch_runs)   # FWS already excluded
        out = []
        for d in diagnoses:
            if not is_auto(d.get("bucket", "")):
                continue                                # non-AUTO -> never auto-applied here
            if not self.drafter:
                continue                                # no drafter -> nothing to safely apply
            imp = self.drafter(d, batch_runs, successes)
            if imp is not None:
                out.append(imp)
        return out

    # ---- sequential, RESUMABLE apply -> gate -> commit/rollback ------------
    def apply_resumable(self, improvements: List[Improvement], snap_root, ledger, persist):
        """One change at a time, each decision durably checkpointed via `persist(ledger)`
        so a crash mid-`improve` resumes at the exact next undecided change — without
        re-running the batch and without re-applying an already decided change.

        ledger = {"started": {imp_id: subdir}, "decided": [decision...], "initial_score": int|None}
        A change is durable through three states: snapshot-written (started) -> mutated ->
        decided. On resume, a 'started' but not 'decided' change is first RESTORED from its
        on-disk snapshot (undoing any partial mutation), then retried cleanly."""
        snap_root = Path(snap_root)
        ledger.setdefault("started", {})
        ledger.setdefault("decided", [])
        ledger.setdefault("initial_score", None)

        # (re)establish the holdout baseline from the CURRENT committed surface state.
        measured_now = self.regressor.set_baseline()
        if ledger["initial_score"] is None:
            ledger["initial_score"] = measured_now
            persist(ledger)
        initial = ledger["initial_score"]
        decided_ids = {d["id"] for d in ledger["decided"]}

        for imp in improvements:
            if imp.id in decided_ids:
                continue                                  # already handled in a prior (pre-crash) pass
            # a 'started' but undecided change crashed mid-apply: undo it before retrying
            if imp.id in ledger["started"]:
                self.surface.restore(Surface.read_snapshot(snap_root / ledger["started"][imp.id]))

            if imp.kind == "budget" and not imp.within_cap:
                ledger["decided"].append({"id": imp.id, "kind": imp.kind,
                                          "targeted": list(imp.targeted_cids), "decision": "rollback",
                                          "reason": "budget proposal exceeds cap; refused (not applied)",
                                          "rollback_verified": True})
                persist(ledger)
                continue

            snap = self.surface.snapshot()
            subdir = snap_root / imp.id
            Surface.write_snapshot(snap, subdir)
            ledger["started"][imp.id] = imp.id            # snapshot durable BEFORE mutate
            persist(ledger)

            imp.mutate(self.surface)
            verdict = self.regressor.gate(imp)
            if verdict.adopt:
                self.regressor.accept(verdict.holdout_after)
                decision = {"id": imp.id, "kind": imp.kind, "targeted": list(imp.targeted_cids),
                            "decision": "adopt", "verdict": verdict.to_dict()}
            else:
                self.surface.restore(snap)                # atomic, hash-verified
                decision = {"id": imp.id, "kind": imp.kind, "targeted": list(imp.targeted_cids),
                            "decision": "rollback", "verdict": verdict.to_dict(),
                            "rollback_verified": True}
            ledger["decided"].append(decision)
            ledger["started"].pop(imp.id, None)
            persist(ledger)

        applied = [d for d in ledger["decided"] if d["decision"] == "adopt"]
        rolled_back = [d for d in ledger["decided"] if d["decision"] == "rollback"]
        net_delta = self.regressor.baseline_score() - initial
        return applied, rolled_back, net_delta

    def apply(self, improvements: List[Improvement]):
        """Non-persisted convenience wrapper (returns the same triple). Used where resume
        is not needed; the loop uses apply_resumable with a durable ledger."""
        import tempfile
        return self.apply_resumable(improvements, snap_root=tempfile.mkdtemp(),
                                    ledger={}, persist=lambda _l: None)

    def run(self, diagnoses, batch_runs):
        return self.apply(self.build(diagnoses, batch_runs))

    def run_resumable(self, diagnoses, batch_runs, snap_root, ledger, persist):
        return self.apply_resumable(self.build(diagnoses, batch_runs), snap_root, ledger, persist)
