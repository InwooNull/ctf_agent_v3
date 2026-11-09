"""Diagnoser — classify each FAILED trajectory into an actionable bucket (Phase 44b).

Design rules (in priority order, all enforced by tests):

1. FAIL-SAFE ASYMMETRY. AUTO buckets (knowledge_gap / experience_gap / budget /
   approach) let the loop self-modify its own skills/routing/budget. Non-AUTO buckets
   (tool_gap / harness_bug / human_grade / cyber_blocked / fws / ambiguous) do not —
   they are logged for a human, skipped, or logged once. **When confidence that this is
   an AUTO case is not high, we classify NON-AUTO.** A wrong self-modification is far
   more dangerous than a wrong human-gate log, so the tie always breaks toward "do not
   self-modify". The residual fail-safe bucket is `ambiguous` (non-AUTO).

2. RULE TABLE FIRST, LLM ONLY FOR THE RESIDUAL. Crisp trace signals (an explicit
   [cyber] refusal, a tool-not-found, a deploy/harness fault, a recv-cap hit, an
   FLAG_WITHOUT_SOLUTION verdict, budget exhaustion with work done) are classified
   deterministically with no model call. Only trajectories the rules cannot decide are
   passed to the agent's own Claude judgment (`judge`), and even then a non-confident or
   absent judgment falls back to `ambiguous` (non-AUTO). This bounds token use and keeps
   diagnosis reproducible.

3. FWS TAGGING. A trajectory the verifier marked FLAG_WITHOUT_SOLUTION looks like it
   reached a flag but has no container evidence chain. It is tagged `fws=True`, routed
   to a NON-AUTO bucket, and excluded from the experience-promotion success set
   (`promotable_successes`) so Phase 44c can never promote a false positive as a success
   memory. We only READ the verifier/FWS output — we never modify the guard.

Blindness: the diagnoser reads ONLY the agent's own trace signals (already extracted
from its transcript/session by the blind runner) plus the verified verdict. It never
reads a scorer key, a vault split, or the withheld flag.
"""
from dataclasses import dataclass, field, asdict
from pathlib import Path

# --- buckets and their disposition ------------------------------------------
AUTO_BUCKETS = ("knowledge_gap", "experience_gap", "budget", "approach")
# Which AUTO self-modify SURFACE each AUTO bucket edits (Phase 46b). budget is kept
# distinct from approach: a budget change raises the per-category/difficulty experiment
# cap (only when the run was genuinely progressing and hit the cap); an approach change
# is a KNOWLEDGE edit (a cheatsheet/routing note "if you see this stalled/looping signal,
# pivot or debug the approach — more budget will not help").
AUTO_SURFACE = {
    "knowledge_gap": "skill",       # skills/<cat>/*.md
    "approach": "skill",            # skills/<cat>/*.md — a pivot/debug note (NOT more budget)
    "experience_gap": "experience",  # the experience store
    "budget": "budget",             # the per-category/difficulty budget config (within cap)
}
# disposition: how Phase 44c is ALLOWED to act on a bucket.
#   AUTO       : self-modify within the autonomy boundary (skills/routing/experience/budget)
#   HUMAN_GATE : append a request to growth/requests.md; never auto-applied
#   SKIP       : mark the challenge unreachable; do not retry (human-grade difficulty)
#   LOG_ONCE   : one line in growth/requests.md; never retried (a [cyber] weaponization block)
DISPOSITION = {
    "knowledge_gap": "AUTO",
    "experience_gap": "AUTO",
    "budget": "AUTO",
    "approach": "AUTO",
    "tool_gap": "HUMAN_GATE",
    "harness_bug": "HUMAN_GATE",
    "fws": "HUMAN_GATE",          # an integrity event: surface to a human, never auto-react
    "ambiguous": "HUMAN_GATE",    # the fail-safe sink for undecidable cases
    "human_grade": "SKIP",
    "cyber_blocked": "LOG_ONCE",
}
JUDGE_CONFIDENCE_MIN = 0.66       # a residual AUTO verdict below this -> ambiguous (fail-safe)


def is_auto(bucket):
    return DISPOSITION.get(bucket) == "AUTO"


@dataclass
class Diagnosis:
    cid: str
    bucket: str
    disposition: str
    actionable: bool              # True only when disposition == AUTO
    fws: bool = False
    confidence: float = 1.0
    source: str = "rule"          # rule | judge | fail-safe
    reason: str = ""

    def to_dict(self):
        return asdict(self)


def _is_fws(run):
    """A run is FWS if the verifier said so OR a trace signal flags it. Defensive: this
    holds even if some upstream bug set run.solved=True on an FWS trajectory."""
    sig = getattr(run, "signals", {}) or {}
    return bool(sig.get("fws")) or getattr(run, "outcome", "") == "FLAG_WITHOUT_SOLUTION"


def promotable_successes(runs):
    """The ONLY runs Phase 44c may promote as success experience: genuinely solved AND
    not FWS. An FWS trajectory is excluded even if its `solved` flag is (wrongly) True."""
    return [r for r in runs if getattr(r, "solved", False) and not _is_fws(r)]


# --- the deterministic rule table -------------------------------------------
def _rule_bucket(run):
    """Return (bucket, reason) when a crisp signal decides it, else (None, "") so the
    caller sends it to the residual judge. NON-AUTO signals are checked FIRST so a
    co-occurring AUTO-looking signal can never pull an unsafe case into self-modify."""
    s = getattr(run, "signals", {}) or {}
    give_up_kind = s.get("give_up_kind", "")

    # --- NON-AUTO first (fail-safe precedence) ---
    if s.get("cyber_blocked"):
        return "cyber_blocked", "explicit [cyber] weaponization refusal in the trace"
    if _is_fws(run):
        return "fws", "verifier verdict FLAG_WITHOUT_SOLUTION (reported flag, no evidence chain)"
    if s.get("harness_error") or s.get("deploy_fault") or s.get("recv_cap_hit"):
        return "harness_bug", "a harness/deploy fault or recv-cap limited the run, not the agent"
    if s.get("tool_missing") or give_up_kind == "tool":
        return "tool_gap", "a needed tool was absent / the agent self-reported a tool gap"
    if s.get("human_grade_hint"):
        return "human_grade", "flagged human-grade difficulty; mark unreachable, do not retry"

    # --- crisp AUTO: budget VS approach (Phase 46b) ---
    # A budget-exhausted run is only `budget` if it was genuinely PROGRESSING when it hit
    # the cap. If it was STALLED/looping (an impl bug it kept retrying, the same error
    # class repeatedly, or no new observations), more budget will not help — that is an
    # `approach` problem (pivot/debug), so it must NOT be auto-labelled budget. Both are
    # AUTO, so this split does not touch the AUTO-vs-non-AUTO fail-safe asymmetry.
    budget_hit = s.get("budget_exhausted") or getattr(run, "outcome", "") == "BUDGET_EXHAUSTED"
    if budget_hit:
        n_ok = s.get("n_exp_ok", 0)
        stalled = (give_up_kind == "impl"                # self-reported own-code/implementation bug
                   or bool(s.get("stalled"))
                   or bool(s.get("repeated_error_class"))   # same error class ≥2x
                   or bool(s.get("no_observation_growth")))  # experiments stopped yielding new info
        if stalled:
            return "approach", ("budget was hit but the approach was STALLED/looping "
                                "(impl bug / repeated error class / no new observations) — "
                                "pivot or debug the approach; more budget will not help")
        if n_ok and n_ok > 0:
            return "budget", ("budget exhausted while making monotonic progress "
                              "(experiments kept yielding new observations, cut off at the cap) — "
                              "raise the per-category/difficulty budget within cap")
        # budget 'hit' but nothing ran ok and not stalled -> tooling never worked; residual
        return None, ""

    # everything else is residual -> the judge (then fail-safe)
    return None, ""


class Diagnoser:
    """Classify a list of RunOutcome (failures) into Diagnosis records.

    judge: optional callable(signals: dict, excerpt: str) -> (bucket:str|None, confidence:float).
           This is the agent's own Claude self-judgment, invoked ONLY for residual cases.
           Absent/None -> every residual becomes `ambiguous` (the strict fail-safe)."""

    def __init__(self, judge=None, confidence_min=JUDGE_CONFIDENCE_MIN):
        self.judge = judge
        self.confidence_min = confidence_min

    def diagnose_one(self, run) -> Diagnosis:
        fws = _is_fws(run)
        bucket, reason = _rule_bucket(run)
        source = "rule"
        confidence = 1.0

        if bucket is None:
            # residual -> LLM judgment, with the fail-safe asymmetry applied to its answer
            bucket, confidence, source = self._residual(run)

        return Diagnosis(cid=getattr(run, "cid", ""), bucket=bucket,
                         disposition=DISPOSITION[bucket], actionable=is_auto(bucket),
                         fws=fws, confidence=round(float(confidence), 3), source=source,
                         reason=reason or "")

    def _residual(self, run):
        s = getattr(run, "signals", {}) or {}
        excerpt = s.get("transcript_excerpt", "")
        if self.judge is None:
            return "ambiguous", 1.0, "fail-safe"      # no judge -> never self-modify
        try:
            bucket, confidence = self.judge(s, excerpt)
        except Exception:
            return "ambiguous", 1.0, "fail-safe"
        if not bucket or bucket not in DISPOSITION:
            return "ambiguous", float(confidence or 0.0), "fail-safe"
        # THE ASYMMETRY: a judge's AUTO verdict must clear the confidence bar; otherwise
        # we refuse to self-modify and fall to the non-AUTO ambiguous sink. A judge's
        # NON-AUTO verdict is accepted at any confidence (erring toward not self-modifying).
        if is_auto(bucket) and float(confidence) < self.confidence_min:
            return "ambiguous", float(confidence), "fail-safe"
        return bucket, float(confidence), "judge"

    def diagnose(self, runs):
        return [self.diagnose_one(r).to_dict() for r in runs]


# --- HUMAN-GATE / LOG-ONCE logging (writes ONLY growth/requests.md) ----------
def write_requests(diagnoses, path):
    """Append the non-AUTO diagnoses to growth/requests.md as human requests. A
    cyber_blocked entry for a cid is logged at most ONCE across the whole file (no
    retry-spam). Returns the list of entries actually written this call."""
    path = Path(path)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    lines, wrote = [], []
    for d in diagnoses:
        disp = d["disposition"]
        if disp == "AUTO":
            continue
        tag = {"HUMAN_GATE": "HUMAN-GATE", "SKIP": "SKIP", "LOG_ONCE": "LOG-ONCE"}[disp]
        key = f"[{tag}] {d['bucket']} :: {d['cid']}"
        if d["bucket"] == "cyber_blocked" and (key in existing or key in "\n".join(lines)):
            continue                     # dedup: log a [cyber] block for a cid only once
        lines.append(f"- {key} — {d.get('reason','')} (confidence {d.get('confidence')}, "
                     f"source {d.get('source')})")
        wrote.append(d)
    if lines:
        header = "" if existing else "# growth/requests.md — HUMAN-GATE requests (never auto-applied)\n\n"
        with path.open("a", encoding="utf-8") as f:
            if header:
                f.write(header)
            f.write("\n".join(lines) + "\n")
    return wrote
