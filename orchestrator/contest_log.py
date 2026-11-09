"""Phase CM4: contest-mode disclosure + knowledge glue.

Fixes three WHITEHAT gaps: no writeup/disclosure log, '날것'(raw) execution with no
skill_pack injection, and no separation of contest learning from the blind bench.

  WriteupLog   -> store/contest/<run>/writeup_log.jsonl : model name, prompt, per-step
                  process, and AI output, auto-recorded for AI-disclosure rules. Contest
                  flags may be logged by value. This is the RAW MATERIAL the human
                  submitter turns into the required "my work vs AI + how verified" note.
  CandidateBoard -> store/contest/<run>/candidates.jsonl : candidate flag + evidence +
                  confidence SHOWN TO THE USER for MANUAL submission. There is NO submit
                  call anywhere here (contest rules; keeps attempts at 0).
  skill_prompt -> reuses orchestrator.skill_pack.inject so a contest run gets the same
                  knowledge/routing pack as bench (no raw solving).
  ContestExperience -> store/contest/experience_contest.jsonl, tagged source="contest",
                  kept SEPARATE from the blind store/experience_*.jsonl so contest
                  learning can never contaminate blind measurement.

Reuses governance/other modules, edits none. Stdlib only.
"""
import json
import time
from pathlib import Path

from orchestrator import skill_pack

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STORE = PROJECT_ROOT / "store"


def contest_run_dir(run_id, store_root=DEFAULT_STORE):
    """store/contest/<run_id>/ — created if absent."""
    d = Path(store_root) / "contest" / str(run_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


class WriteupLog:
    """Append-only disclosure log for one contest run."""

    def __init__(self, run_dir, clock=time.time):
        self.path = Path(run_dir) / "writeup_log.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock

    def record(self, cid, *, model, prompt, output, step=None, **extra):
        """Log one AI interaction for challenge `cid`. Flag values are allowed."""
        rec = {"ts": round(self._clock(), 6), "cid": cid, "model": model,
               "step": step, "prompt": prompt, "output": output}
        rec.update(extra)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def entries(self):
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]


class CandidateBoard:
    """Candidates surfaced to the user for MANUAL submission. No auto-submit, ever."""

    MANUAL = "manual_submit_by_user"

    def __init__(self, run_dir):
        self.path = Path(run_dir) / "candidates.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def present(self, cid, flag, *, verdict, confidence, evidence_refs=None):
        """Record a candidate for the user and return a human-readable line. This NEVER
        submits anywhere; the user submits by hand (contest rules)."""
        rec = {"cid": cid, "flag": flag, "verdict": verdict,
               "confidence": round(float(confidence), 3),
               "evidence_refs": list(evidence_refs or []),
               "submitted": False, "action": self.MANUAL}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        tag = "SOLVE" if verdict == "VERIFIED" else "candidate"
        return (f"[{tag}] {cid}: {flag}  (confidence {rec['confidence']}, "
                f"verdict={verdict}, evidence={rec['evidence_refs']}) "
                f"-> submit manually")

    def all(self):
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def verified(self):
        return [c for c in self.all() if c["verdict"] == "VERIFIED"]


# Contest category -> skills/<pack> directory, where the two names differ. The
# classifier/triage emits the short category token ("rev"); the knowledge pack lives
# under its full name ("reverse"). Without this alias skill_pack.has_pack("rev") is
# False and the rev pack silently never injects (a C1->C0 degrade). skill_pack.py is
# governance-frozen, so the alias lives here, at the single injection call site.
_PACK_ALIAS = {"rev": "reverse"}


def pack_name(category):
    """The skills/<dir> pack name for a contest category (identity unless aliased)."""
    return _PACK_ALIAS.get(category, category)


def skill_prompt(category, base_prompt, full=True, header=None):
    """Inject the category knowledge/routing pack into a prompt (no raw solving).

    Thin reuse of orchestrator.skill_pack.inject; returns base_prompt unchanged when
    the category has no pack. The category is resolved to its pack name first (so the
    short token 'rev' finds skills/reverse)."""
    category = pack_name(category)
    if not skill_pack.has_pack(category):
        return base_prompt
    return skill_pack.inject(base_prompt, category, full=full, header=header)


class ContestExperience:
    """Contest learning, tagged and stored SEPARATELY from the blind bench store."""

    def __init__(self, store_root=DEFAULT_STORE):
        self.path = Path(store_root) / "contest" / "experience_contest.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, record):
        """Append one experience record, force-tagged source='contest'."""
        rec = dict(record)
        rec["source"] = "contest"            # never 'bench'/'blind'
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def all(self):
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]
