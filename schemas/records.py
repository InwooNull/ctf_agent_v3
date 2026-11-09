"""Data contracts for the CTF agent (Phase 0).

All records are plain dataclasses with enum-like string fields validated in
__post_init__, plus to_dict/from_dict for JSON round-tripping.
"""
from dataclasses import asdict, dataclass, field
from typing import Optional

PRIORITY_BANDS = ("high", "mid", "low")
HYPOTHESIS_STATUSES = ("proposed", "testing", "supported", "refuted", "held")
EXECUTION_STATUSES = ("ok", "error", "timeout", "aborted")
HYPOTHESIS_JUDGMENTS = ("support", "refute", "inconclusive", "deferred")
CANDIDATE_STATUSES = ("UNVERIFIED", "VERIFIED", "REJECTED")


def _check(value, allowed, name):
    if value not in allowed:
        raise ValueError(f"{name}={value!r} not in {allowed}")


@dataclass
class Hypothesis:
    id: str
    challenge_id: str
    statement: str
    rationale: str
    refutation_condition: str
    priority_band: str = "mid"
    status: str = "proposed"
    experiment_ids: list = field(default_factory=list)

    def __post_init__(self):
        _check(self.priority_band, PRIORITY_BANDS, "priority_band")
        _check(self.status, HYPOTHESIS_STATUSES, "status")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class Experiment:
    id: str
    hypothesis_id: str
    tool: str
    argv: list
    env: dict
    cwd: str
    timeout: float
    dedup_key: str
    execution_status: str
    observation_ref: Optional[str]
    hypothesis_judgment: str
    evidence_refs: list = field(default_factory=list)
    nondeterministic: bool = False

    def __post_init__(self):
        _check(self.execution_status, EXECUTION_STATUSES, "execution_status")
        _check(self.hypothesis_judgment, HYPOTHESIS_JUDGMENTS, "hypothesis_judgment")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class Candidate:
    value: str
    confidence: float
    evidence_refs: list = field(default_factory=list)
    status: str = "UNVERIFIED"

    def __post_init__(self):
        _check(self.status, CANDIDATE_STATUSES, "status")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class Checkpoint:
    run_id: str
    challenge_id: Optional[str]
    active_hypotheses: list  # list[Hypothesis]
    budget_spent: dict       # {"time_s", "rounds", "attempts"}
    next_action: dict        # {"kind": dispatch|experiment|done, ...cursor}
    safe_point: dict         # {"label", "event_seq", "command_seq"}

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        d = dict(d)
        d["active_hypotheses"] = [Hypothesis.from_dict(h) for h in d["active_hypotheses"]]
        return cls(**d)
