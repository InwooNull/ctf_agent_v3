"""Low-cost first pass + decoy detection.

Before spending a real solve budget, a cheap pass checks for the obvious: a flag left
in flag.txt / .env / hard-coded in a public source file (easy points). The same layer
also screens out DECOYS — the ACDC "THIS IS A SAMPLE FLAG" trap, and any value that
merely matches the flag format but carries no evidence that it was produced by a solve.

These are host-side reads of PUBLIC challenge files only (never vault, never the scorer
keys). first_pass returns candidate (path, value) hits; the caller still runs them
through the decoy filter and the reproduce-before-submit gate — a planted sample flag
is found here but rejected there.
"""
import re
from pathlib import Path

DEFAULT_FLAG_RE = r"[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}"

# markers of a decoy / placeholder, not a real flag
DECOY_MARKERS = (
    "sample flag", "this is a sample", "example flag", "sample_flag",
    "your flag here", "flag goes here", "changeme", "change me",
    "redacted", "placeholder", "dummy flag", "not the flag", "fake flag",
    "xxxx", "....", "test flag", "todo",
)

# files that frequently leak a flag outright
LEAKY_NAMES = ("flag.txt", "flag", ".env", "secret.txt", "key.txt", "flag.json")
# only scan smallish text files in the first pass
_MAX_SCAN_BYTES = 262144
_TEXT_SUFFIXES = {".txt", ".env", ".json", ".py", ".md", ".cfg", ".ini", ".yaml",
                  ".yml", ".html", ".js", ".c", ".h", ".log", ".csv", ""}


def is_decoy(value, evidence_refs=()):
    """True if `value` should NOT be trusted as a real flag.

    Rejects empty values, known placeholder/sample markers, and any value with no
    evidence_refs (format-only, i.e. a guess). Keeps the finder honest — a real solve
    always carries an evidence chain.
    """
    if not value or not str(value).strip():
        return True
    low = str(value).lower()
    if any(m in low for m in DECOY_MARKERS):
        return True
    if not evidence_refs:
        return True
    return False


def _looks_text(path):
    return path.suffix.lower() in _TEXT_SUFFIXES


def first_pass(challenge_dir, flag_re=DEFAULT_FLAG_RE, max_files=200):
    """Cheap scan of public files for an exposed flag.

    Returns a list of {"path", "value", "leaky_name", "decoy"} hits (deduped by value).
    `leaky_name` flags a hit from flag.txt/.env-style files. `decoy` pre-labels obvious
    placeholders. No value is trusted here; the caller gates it.
    """
    root = Path(challenge_dir)
    rx = re.compile(flag_re)
    hits, seen = [], set()
    files = [p for p in sorted(root.rglob("*")) if p.is_file()][:max_files]
    for p in files:
        leaky = p.name.lower() in LEAKY_NAMES
        if not leaky and not _looks_text(p):
            continue
        try:
            if p.stat().st_size > _MAX_SCAN_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in rx.finditer(text):
            val = m.group(0)
            if val in seen:
                continue
            seen.add(val)
            hits.append({"path": str(p.relative_to(root)), "value": val,
                         "leaky_name": leaky, "decoy": is_decoy(val, evidence_refs=["first_pass"])})
    return hits
