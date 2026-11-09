"""Mock solver: replays a scenario deterministically. No real tools, no LLM.

Scenario format (embedded in the challenge dict as "scenario"):
{
  "expected_flag": "hitcon{...}",          # mock submit oracle
  "hypotheses": [{
     "statement", "rationale", "refutation_condition", "priority_band",
     "flag": optional flag yielded when the hypothesis is supported,
     "experiments": [{
        "tool", "version", "argv", "env", "cwd", "timeout", "input_files", "nondeterministic",
        # scenario-only (not part of the dedup key):
        "duration_s", "execution_status", "observation", "judgment"
     }]
  }]
}
"""
import random

from schemas.records import Hypothesis

BAND_ORDER = {"high": 0, "mid": 1, "low": 2}
DEFAULT_TIMEOUT_S = 30


class MockSolver:
    def __init__(self, scenario, seed=0, clock=None):
        self.scenario = scenario
        self.seed = seed
        self.clock = clock
        self.execution_count = 0
        indexed = list(enumerate(scenario.get("hypotheses", [])))
        indexed.sort(key=lambda p: (BAND_ORDER[p[1].get("priority_band", "mid")], p[0]))
        self._hyps = [h for _, h in indexed]

    def propose_hypotheses(self, challenge_id):
        return [
            Hypothesis(
                id=f"{challenge_id}-H{i}",
                challenge_id=challenge_id,
                statement=h["statement"],
                rationale=h.get("rationale", ""),
                refutation_condition=h.get("refutation_condition", ""),
                priority_band=h.get("priority_band", "mid"),
            )
            for i, h in enumerate(self._hyps)
        ]

    def num_experiments(self, hyp_index):
        return len(self._hyps[hyp_index].get("experiments", []))

    def experiment_spec(self, hyp_index, exp_index):
        raw = self._hyps[hyp_index]["experiments"][exp_index]
        spec = {
            "tool": raw["tool"],
            "version": raw.get("version", "mock"),
            "argv": list(raw.get("argv", [])),
            "env": dict(raw.get("env", {})),
            "cwd": raw.get("cwd", "."),
            "timeout": raw.get("timeout", DEFAULT_TIMEOUT_S),
            "input_files": list(raw.get("input_files", [])),
            "nondeterministic": bool(raw.get("nondeterministic", False)),
            "duration_s": raw.get("duration_s", 1),
            "execution_status": raw.get("execution_status", "ok"),
            "observation": raw.get("observation", ""),
        }
        return spec

    def execute(self, spec):
        """Fake execution -> (execution_status, observation)."""
        self.execution_count += 1
        duration = spec["duration_s"]
        status = spec["execution_status"]
        if duration > spec["timeout"]:
            status, duration = "timeout", spec["timeout"]
        if self.clock is not None and hasattr(self.clock, "advance"):
            self.clock.advance(duration)
        rng = random.Random(f"{self.seed}|{spec['tool']}|{'\x00'.join(spec['argv'])}")
        return status, f"{spec['observation']} [mock:{rng.getrandbits(32):08x}]"

    def judge(self, hyp_index, exp_index, observation):
        return self._hyps[hyp_index]["experiments"][exp_index].get("judgment", "inconclusive")

    def candidate_flag(self, hyp_index):
        return self._hyps[hyp_index].get("flag")

    def verify(self, value):
        expected = self.scenario.get("expected_flag")
        return "VERIFIED" if expected is not None and value == expected else "REJECTED"
