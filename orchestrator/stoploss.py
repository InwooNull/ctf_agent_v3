"""Per-challenge budget + stop-loss policy (orchestrator layer).

Two ACDC failure modes motivate this: pouring unbounded effort into one challenge,
and having no give-up signal. The orchestrator enforces a per-challenge budget
(experiments / wall-seconds / a token proxy) and a stop-loss that fires when progress
stalls (K consecutive rounds with zero new information gain) or the budget is spent.

Near-miss recovery: if the stop-loss would fire but we are HOLDING A VERIFIED exploit
chain (a reproduced solve that only needs a little more room — e.g. the pwn runs that
timed out with a working chain in hand), the budget is raised ONCE and a fresh stall
window is granted; if it stalls again it STOPs for good. This recovers the "verified
chain, out of budget" near-misses without unbounded spending.

The whole state serializes to/from a dict so it rides in the run checkpoint and
survives resume.
"""
CONTINUE = "CONTINUE"
RAISE_ONCE = "RAISE_ONCE"
STOP = "STOP"

DEFAULT_CAPS = {"experiments": 12, "wall_s": 1200.0, "tokens": 0}


class StopLoss:
    def __init__(self, caps=None, no_progress_k=3, raise_factor=1.5):
        self.caps = dict(caps or DEFAULT_CAPS)
        self.spent = {k: 0 for k in self.caps}
        self.gains = []            # per-round info-gain amounts (0 == no new info)
        self.k = no_progress_k
        self.raise_factor = raise_factor
        self.raised = False

    # ---- recording ------------------------------------------------------
    def record_round(self, info_gain=0, experiments=1, wall_s=0.0, tokens=0):
        """Log one round: its info gain and the resources it consumed."""
        self.gains.append(float(info_gain))
        self.spent["experiments"] = self.spent.get("experiments", 0) + experiments
        self.spent["wall_s"] = self.spent.get("wall_s", 0.0) + wall_s
        self.spent["tokens"] = self.spent.get("tokens", 0) + tokens

    # ---- signals --------------------------------------------------------
    def trailing_stall(self):
        """Number of consecutive most-recent rounds with zero info gain."""
        n = 0
        for g in reversed(self.gains):
            if g > 0:
                break
            n += 1
        return n

    def over_budget(self):
        for key, cap in self.caps.items():
            if cap and self.spent.get(key, 0) >= cap:
                return key
        return None

    def _triggered(self):
        return bool(self.over_budget()) or self.trailing_stall() >= self.k

    # ---- the decision ---------------------------------------------------
    def decide(self, has_verified_chain=False):
        """CONTINUE, RAISE_ONCE (near-miss recovery), or STOP."""
        if not self._triggered():
            return CONTINUE
        if has_verified_chain and not self.raised:
            self._raise()
            return RAISE_ONCE
        return STOP

    def _raise(self):
        for key in self.caps:
            if self.caps[key]:
                self.caps[key] = type(self.caps[key])(self.caps[key] * self.raise_factor)
        self.raised = True
        self.gains = []  # fresh stall window so the raise actually buys more rounds

    # ---- checkpoint -----------------------------------------------------
    def to_dict(self):
        return {"caps": dict(self.caps), "spent": dict(self.spent), "gains": list(self.gains),
                "k": self.k, "raise_factor": self.raise_factor, "raised": self.raised}

    @classmethod
    def from_dict(cls, d):
        obj = cls(caps=d["caps"], no_progress_k=d["k"], raise_factor=d["raise_factor"])
        obj.spent = dict(d["spent"])
        obj.gains = list(d["gains"])
        obj.raised = d["raised"]
        return obj
