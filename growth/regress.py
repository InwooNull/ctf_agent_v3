"""Regressor — the dual-condition, blind, variance-conservative adoption gate (Phase 44c).

A self-modification is ADOPTED only if BOTH hold (otherwise it is rolled back):
  (a) DEV-TARGET FLIP  — every dev cid the change TARGETED (a previous failure) is now
      SOLVED after the change. Without a flip the change did not do what it claimed, so a
      coincidental holdout tie must NOT be read as improvement.
  (b) HOLDOUT NO-DROP  — the holdout regression score does not strictly decrease
      (maintain-or-improve). ANY strict drop -> rollback, even if "within noise"
      (conservative: requirement 4).

Variance handling: adoption never rests on a holdout GAIN (which could be LLM noise) —
it rests on the deterministic dev-target flip plus holdout no-drop. So a noisy holdout
gain cannot cause a false adopt, and a noisy holdout drop causes a (safe) rollback.

Blindness: `dev_eval` and `holdout_eval` are injected callables that internally use the
existing BLIND runner on --network none and the orchestrator's unlock->grade->relock for
scoring. The regressor only reads pass/fail they return; it never reads a scorer key, a
withheld flag, or a vault split, and it never modifies a governance/verifier/FWS file.
"""
from dataclasses import dataclass, asdict


@dataclass
class GateVerdict:
    adopt: bool
    flip: bool                     # condition (a)
    no_drop: bool                  # condition (b)
    holdout_before: int
    holdout_after: int
    delta: int
    targeted: list
    dev_after: dict                # cid -> solved (the re-evaluated targets)
    reason: str = ""

    def to_dict(self):
        return asdict(self)


class Regressor:
    def __init__(self, dev_eval, holdout_eval):
        """dev_eval(cids)->{cid:solved}; holdout_eval()->{cid:solved} (blind, graded).
        Both evaluate the CURRENT managed-surface state (so call AFTER a change is applied
        to see its effect, and after a rollback to see it reverted)."""
        self.dev_eval = dev_eval
        self.holdout_eval = holdout_eval
        self._baseline_score = None       # accepted holdout score (updates as changes adopt)
        self._initial_score = None

    @staticmethod
    def _score(res):
        return sum(1 for v in res.values() if v)

    def set_baseline(self):
        """Measure the holdout BEFORE any change this cycle. Returns the score."""
        s = self._score(self.holdout_eval())
        self._baseline_score = s
        self._initial_score = s
        return s

    def baseline_score(self):
        return self._baseline_score

    def initial_score(self):
        return self._initial_score

    def accept(self, new_holdout_score):
        """After an adoption, the accepted state's holdout score becomes the new baseline
        so the next sequential change is gated against the already-improved state."""
        self._baseline_score = new_holdout_score

    def gate(self, improvement):
        """Evaluate conditions (a) and (b) for a single already-applied improvement."""
        targeted = list(getattr(improvement, "targeted_cids", []) or [])
        # (a) dev-target flip — the targeted previous-failures must now be solved
        dev_after = self.dev_eval(targeted) if targeted else {}
        flip = bool(targeted) and all(dev_after.get(c, False) for c in targeted)
        # (b) holdout no strict drop
        after = self._score(self.holdout_eval())
        before = self._baseline_score
        no_drop = after >= before
        adopt = flip and no_drop
        if adopt:
            reason = "adopt: dev-target flipped and holdout did not drop"
        elif not flip:
            reason = "rollback: dev-target NOT fixed (no fail->solved flip); a holdout tie is not improvement"
        else:
            reason = "rollback: holdout score strictly dropped (conservative on any drop)"
        return GateVerdict(adopt=adopt, flip=flip, no_drop=no_drop,
                           holdout_before=before, holdout_after=after, delta=after - before,
                           targeted=targeted, dev_after=dev_after, reason=reason)
