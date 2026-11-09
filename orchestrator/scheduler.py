"""Inter-challenge resource reallocation (flags-per-hour).

Given a queue of challenges, work the one with the best expected return per unit cost
first, and when a challenge exhausts its budget (stop-loss) move automatically to the
next most promising one — under a global time / usage ceiling. This is the "don't sink
the whole session into one problem" policy at the queue level.

  priority(c) = expected_value(c) / est_cost(c)
  expected_value(c) = score(c) / difficulty_weight(difficulty(c))

Difficulty starts as a coarse estimate (easy/med/hard) and is updated by feedback:
a stop-loss / no-progress bumps a challenge harder (lowering its priority if revisited),
observed progress can ease it. Ties break by the original queue order (deterministic).
"""
DIFFICULTY_WEIGHT = {"easy": 1.0, "med": 2.0, "hard": 4.0}
_ORDER = ["easy", "med", "hard"]
_EPS = 1e-9


class Scheduler:
    def __init__(self, challenges, global_caps=None):
        """challenges: [{id, score, difficulty, est_cost}]. global_caps: {time_s, experiments}."""
        self.items = {}
        self.order = []
        for c in challenges:
            cid = c["id"]
            self.items[cid] = {
                "id": cid, "score": float(c.get("score", 1.0)),
                "difficulty": c.get("difficulty", "med"),
                "est_cost": float(c.get("est_cost", 1.0)),
            }
            self.order.append(cid)
        self.global_caps = dict(global_caps or {})
        self.spent = {"time_s": 0.0, "experiments": 0}
        self.done = {}          # cid -> outcome (solved | stopped | ...)

    # ---- priority -------------------------------------------------------
    def expected_value(self, cid):
        c = self.items[cid]
        return c["score"] / DIFFICULTY_WEIGHT.get(c["difficulty"], 2.0)

    def priority(self, cid):
        c = self.items[cid]
        return self.expected_value(cid) / max(c["est_cost"], _EPS)

    # ---- selection ------------------------------------------------------
    def global_exhausted(self):
        for key, cap in self.global_caps.items():
            if cap and self.spent.get(key, 0) >= cap:
                return key
        return None

    def next(self):
        """Return the id of the next challenge to attempt, or None if the queue is
        drained or the global budget is spent."""
        if self.global_exhausted():
            return None
        pending = [cid for cid in self.order if cid not in self.done]
        if not pending:
            return None
        # max priority; deterministic tie-break by original queue position
        return max(pending, key=lambda cid: (self.priority(cid), -self.order.index(cid)))

    def order_of_attempt(self):
        """The full deterministic order the scheduler would attempt, ignoring spend."""
        return sorted(self.order, key=lambda cid: (-self.priority(cid), self.order.index(cid)))

    # ---- feedback -------------------------------------------------------
    def record_spend(self, time_s=0.0, experiments=0):
        self.spent["time_s"] += time_s
        self.spent["experiments"] += experiments

    def mark_done(self, cid, outcome):
        self.done[cid] = outcome

    def update_difficulty(self, cid, direction):
        """direction: 'harder' (stop-loss / stall) or 'easier' (progress)."""
        cur = self.items[cid]["difficulty"]
        i = _ORDER.index(cur) if cur in _ORDER else 1
        i = min(i + 1, len(_ORDER) - 1) if direction == "harder" else max(i - 1, 0)
        self.items[cid]["difficulty"] = _ORDER[i]

    def remaining(self):
        return [cid for cid in self.order if cid not in self.done]
