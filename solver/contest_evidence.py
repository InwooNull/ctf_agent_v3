"""Phase CM4: contest-mode evidence capture + candidate classification.

Directly fixes the WHITEHAT wipe-out's evidence gaps: 0 verified solves, a pile of
placeholder/guessed flags, and "Simple Calc" marked solved but unattributable because
nothing recorded WHERE the flag came from.

It REUSES the bench verifier's discipline (solver/verifier.py): a flag counts only if
it is (a) a plausible flag AND (b) GROUNDED IN EVIDENCE — demonstrably produced, not
guessed. Contest has no scorer key / vault, so the two legs become:

  (a) the flag matches the challenge's declared flag_format, AND
  (b) the flag string actually appears in a captured piece of evidence for this run
      (a target-server response, or the stdout of an execution).

  both      -> VERIFIED              (a real, attributable solve)
  (a) only  -> CANDIDATE_UNVERIFIED  (a guess/placeholder: NO evidence it was produced)
  not (a)   -> CANDIDATE_UNVERIFIED  (bad_format: not even shaped like the flag)

Only VERIFIED is a solve; everything else is quarantined as an unverified candidate.
Classification is LOCAL — it never contacts a server, so there is no auto-submit path.

Stdlib only; governance files are reused, never edited.
"""
import hashlib
import json
import re
from pathlib import Path

VERIFIED = "VERIFIED"
CANDIDATE_UNVERIFIED = "CANDIDATE_UNVERIFIED"

# evidence sources that can ground a flag
SRC_TARGET = "target"      # a response from the challenge target server
SRC_EXEC = "exec"          # stdout/output of an execution (local or in-container)
VALID_SOURCES = (SRC_TARGET, SRC_EXEC)


def flag_prefix(flag_format):
    """The 'flag' in 'flag{...}', or None if the format is not a braced token."""
    if not flag_format:
        return None
    m = re.match(r"^([A-Za-z0-9_]+)\{", str(flag_format).strip())
    return m.group(1) if m else None


def matches_format(flag, flag_format):
    """Does `flag` look like the declared format (prefix + {...})?

    If no usable prefix can be derived from the format, fall back to a generic
    'word{...}' flag shape so a real flag is not rejected for lack of a spec."""
    if not flag or not isinstance(flag, str):
        return False
    pref = flag_prefix(flag_format)
    if pref:
        return re.fullmatch(rf"{re.escape(pref)}\{{.*\}}", flag.strip()) is not None
    return re.fullmatch(r"[A-Za-z0-9_]+\{.*\}", flag.strip()) is not None


def classify(flag, flag_format, evidence_texts):
    """Classify a candidate flag against the format and the captured evidence texts.

    Returns {verdict, reason, grounded_in?}. grounded_in is the index of the evidence
    text that contains the flag (only for VERIFIED)."""
    if not matches_format(flag, flag_format):
        return {"verdict": CANDIDATE_UNVERIFIED, "reason": "bad_format"}
    for i, text in enumerate(evidence_texts or []):
        if text and flag in text:
            return {"verdict": VERIFIED, "reason": "grounded", "grounded_in": i}
    return {"verdict": CANDIDATE_UNVERIFIED, "reason": "no_evidence"}


class ContestVerifier:
    """Captures evidence under a run dir and classifies candidate flags against it.

    Layout under run_dir/evidence/:  <id>.txt (raw capture) + evidence.jsonl (index).
    """

    def __init__(self, run_dir, flag_format=None):
        self.run_dir = Path(run_dir)
        self.ev_dir = self.run_dir / "evidence"
        self.ev_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.ev_dir / "evidence.jsonl"
        self.flag_format = flag_format
        self._items = []           # [{id, source, label, sha256}]
        self._load()

    def _load(self):
        if self.index_path.exists():
            self._items = [json.loads(l) for l in self.index_path.read_text().splitlines() if l.strip()]

    def capture(self, source, text, label=""):
        """Record one evidence item (a target response or an execution output).

        Returns its evidence id. The id is content+count addressed so re-capturing the
        same bytes is idempotent-ish but distinct captures never collide."""
        if source not in VALID_SOURCES:
            raise ValueError(f"evidence source must be one of {VALID_SOURCES}, got {source!r}")
        text = text if isinstance(text, str) else text.decode("utf-8", "replace")
        ev_id = f"ev{len(self._items):04d}_{source}"
        (self.ev_dir / f"{ev_id}.txt").write_text(text, encoding="utf-8")
        rec = {"id": ev_id, "source": source, "label": label,
               "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()}
        with open(self.index_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._items.append(rec)
        return ev_id

    def _texts(self, evidence_refs=None):
        ids = set(evidence_refs) if evidence_refs else None
        out = []
        for it in self._items:
            if ids is not None and it["id"] not in ids:
                continue
            try:
                out.append((it["id"], (self.ev_dir / f"{it['id']}.txt").read_text(errors="replace")))
            except OSError:
                continue
        return out

    def assess(self, flag, evidence_refs=None):
        """Classify a candidate flag against captured evidence.

        Returns a verdict dict with: verdict, reason, flag, confidence, evidence_refs
        (the ids that grounded it, empty when unverified)."""
        pairs = self._texts(evidence_refs)
        res = classify(flag, self.flag_format, [t for _, t in pairs])
        grounded = []
        confidence = 0.2
        if res["verdict"] == VERIFIED:
            grounded = [pairs[res["grounded_in"]][0]]
            confidence = 0.99
        elif res.get("reason") == "bad_format":
            confidence = 0.05
        return {"verdict": res["verdict"], "reason": res["reason"], "flag": flag,
                "confidence": confidence, "evidence_refs": grounded}

    def is_solved(self, cid, candidate):
        """RotationRunner-compatible submit callback: a candidate is a solve ONLY if it
        is VERIFIED (format + evidence). Purely local — never contacts a server."""
        flag = getattr(candidate, "value", candidate)
        refs = getattr(candidate, "evidence_refs", None) or None
        return self.assess(flag, evidence_refs=refs)["verdict"] == VERIFIED
