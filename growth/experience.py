"""Experience lever for the misc/forensics category (Phase 51) — the C2 memory.

Two SEPARATE operations, by design (Phase 51 spec point 4):

1. PROMOTION (always, not gated). A verified-SOLVED, non-FWS dev trajectory is distilled
   into a reusable *methodology* record and appended to the experience store
   (store/experience_misc.jsonl). Storage of verified data is unconditional — it is
   ground truth the loop earned. FWS trajectories are excluded at the source
   (promotion draws only from growth.diagnoser.promotable_successes), so a false positive
   can never become a success memory. A flag is NEVER stored (no_flag=True).

2. INJECTION (holdout-gated). Turning promoted patterns into text the NEXT cycle's active
   skill pack carries (skills/misc/experience.md) is a self-modification, so it goes
   through the regression gate: it is kept ONLY if the holdout score does not strictly
   drop (a bad pattern that hurts the holdout is rolled back and never injected). That
   gating lives in the runner/Improver+Regressor; this module only renders the text and
   loads the store.

Blindness: a record is built from the agent's OWN trace (the winning experiment name, the
tool/technique fingerprint of its transcript, the verified verdict) — never from a scorer
key, a vault split, or the withheld flag.
"""
import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STORE = PROJECT_ROOT / "store" / "experience_misc.jsonl"
INJECTION_FILE = PROJECT_ROOT / "skills" / "misc" / "experience.md"

SCHEMA = {
    "schema": "misc-solve-pattern/v1",
    "fields": {
        "subtype": "challenge subtype / NYU id family (coarse technique domain)",
        "category": "misc | forensics",
        "technique": "the reusable technique fingerprint (tool/approach family)",
        "recipe": "ordered, reproducible methodology steps (no flag, no challenge-specific secret)",
        "signals": "what the winning observation looked like (how you knew it worked)",
        "evidence": "the agent's own winning experiment id (NOT the flag)",
        "confidence": "verified|hypothesis — verified = a graded, non-FWS SOLVED run produced it",
        "source": "the cid + phase the pattern was verified in",
        "no_flag": "flags are NEVER stored here",
    },
}

# Image tools / python libs whose appearance in a transcript fingerprints a technique.
_TOOL_TOKENS = [
    "zsteg", "steghide", "stegseek", "outguess", "binwalk", "foremost", "exiftool",
    "tshark", "tcpdump", "pdftotext", "convert", "zbarimg", "pyzbar", "john", "hashcat",
    "sleuthkit", "fls", "icat", "tsk_recover", "volatility", "vol3", "7z", "7za",
    "tesseract", "cv2", "pytesseract", "strings", "xxd", "base64", "numpy", "pillow", "PIL",
]


def _tech_fingerprint(transcript_text):
    """Deterministic, order-preserving set of tool/technique tokens seen in the trace."""
    seen, low = [], transcript_text.lower()
    for t in _TOOL_TOKENS:
        if t.lower() in low and t not in seen:
            seen.append(t)
    return seen


def _fp_hash(subtype, technique):
    h = hashlib.sha256(("|".join([subtype or ""] + list(technique))).encode()).hexdigest()
    return h[:12]


def load(paths=(DEFAULT_STORE,)):
    """Load pattern records (skip the schema header line)."""
    out = []
    for p in paths:
        p = Path(p)
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("subtype") and rec.get("technique") is not None:
                out.append(rec)
    return out


def build_record(run, transcript_text="", recipe=None):
    """Distill one promotable-success RunOutcome-like object into a pattern record.

    `run` must expose .cid, .category, .signals (dict), and may expose .subtype /
    .winning_exp. `recipe` optionally overrides the auto methodology summary (e.g. a
    one-line human/Claude note for this solve). Never contains a flag.
    """
    sig = getattr(run, "signals", {}) or {}
    subtype = getattr(run, "subtype", None) or sig.get("subtype") or (getattr(run, "category", "") or "misc")
    category = getattr(run, "category", "") or "misc"
    technique = _tech_fingerprint(transcript_text or sig.get("transcript_excerpt", ""))
    evidence = getattr(run, "winning_exp", None) or sig.get("winning_exp", "")
    auto_recipe = (
        "Observed type then applied: " + " -> ".join(technique)
        if technique else "Observed the file type first, then derived the flag in-container."
    )
    return {
        "subtype": str(subtype),
        "category": category,
        "technique": technique,
        "recipe": recipe or auto_recipe,
        "signals": f"in-container experiment {evidence or '(cited)'} printed the flag; verifier SOLVED",
        "evidence": evidence,
        "confidence": "verified",
        "source": f"{getattr(run, 'cid', '')} (Phase 51 cycle)",
        "no_flag": True,
    }


def promote(records, store_path=DEFAULT_STORE):
    """Append NEW pattern records (dedup by (subtype, technique fingerprint)) to the store.
    Writes the schema header if the store is new. Returns the records actually written.
    `records` are dicts from build_record (caller filters to promotable_successes first)."""
    store_path = Path(store_path)
    existing = load((store_path,))
    have = {_fp_hash(r.get("subtype", ""), r.get("technique", [])) for r in existing}
    new = []
    for rec in records:
        key = _fp_hash(rec.get("subtype", ""), rec.get("technique", []))
        if key in have:
            continue
        have.add(key)
        new.append(rec)
    if not store_path.is_file():
        store_path.parent.mkdir(parents=True, exist_ok=True)
        with store_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(SCHEMA) + "\n")
    if new:
        with store_path.open("a", encoding="utf-8") as f:
            for rec in new:
                f.write(json.dumps(rec) + "\n")
    return new


def render_injection(patterns):
    """Render promoted patterns as the skills/misc/experience.md body (injected into the
    next cycle's C1 pack by skill_pack.load_pack, which concatenates skills/misc/*.md).
    Deterministic; contains NO flag. Empty pattern list -> a minimal no-op header."""
    lines = [
        "# Verified solve patterns (experience)",
        "",
        "Methodology distilled from this agent's own VERIFIED (non-FWS, in-container) misc/",
        "forensics solves. Background only: it says which technique family fit which",
        "observation. It contains no flag and no ready answer — you still derive and verify",
        "every flag in-container. Confirm the precondition before reaching for a tool.",
        "",
    ]
    for rec in sorted(patterns, key=lambda r: (r.get("subtype", ""), str(r.get("technique", [])))):
        tech = ", ".join(rec.get("technique", [])) or "(observe-first)"
        lines.append(f"- **{rec.get('subtype','?')}** ({rec.get('category','misc')}): {tech}")
        lines.append(f"  - {rec.get('recipe','')}")
        lines.append(f"  - knew it worked: {rec.get('signals','')}")
    return "\n".join(lines) + "\n"
