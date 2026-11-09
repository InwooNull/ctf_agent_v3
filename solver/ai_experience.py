"""Experience retrieval for the AI category (the C2 lever).

Loads verified attack patterns from store/experience_ai*.jsonl and answers one
question for a given subtype: *what technique class should I try, and in what order?*
It returns a recipe (technique family) plus a ranked list of concrete sub-strategies
to try first. The ranking is learned only from HELD-OUT seed guards (passed in by the
runner), never from the evaluation guards, and it never contains a flag.

This is the ONLY difference between the C0 and C2 configurations: C2 consults this;
C0 does not.
"""
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STORES = (PROJECT_ROOT / "store" / "experience_ai.jsonl",)


def load_patterns(paths=DEFAULT_STORES):
    out = []
    for p in paths:
        p = Path(p)
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("subtype"):  # skip the schema header line
                out.append(rec)
    return out


def retrieve(subtype, benign_rank=None, paths=DEFAULT_STORES):
    """Return {"hit": bool, "pattern": str|None, "benign_rank": [...]} for a subtype.

    `benign_rank` is the seed-learned ordering of benign sub-strategies the runner
    supplies (derived from held-out seed guards). If experience has no positive,
    non-NEGATIVE pattern for the subtype, hit=False and C2 behaves like C0.
    """
    patterns = load_patterns(paths)
    for rec in patterns:
        if rec.get("subtype") != subtype:
            continue
        gp = (rec.get("guard_evasion_pattern") or "")
        if "NEGATIVE" in gp.upper():
            continue  # a known wall is not a technique to try
        return {"hit": True, "pattern": gp,
                "benign_rank": list(benign_rank or [])}
    return {"hit": False, "pattern": None, "benign_rank": list(benign_rank or [])}
