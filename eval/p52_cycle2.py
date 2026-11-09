"""Phase 52 cycle-2 RE-MEASURE driver. Re-run the 6 cycle-1 dev failures K=2 each on the
improved harness (ctfagent-misc:0.6 +pycryptodome; /work persisted across experiments;
crack-class per-exp timeout 90->300s; pids 512) and measure CONVERSIONS vs cycle 1.
Regression guard = holdout no strict drop (mr_1f8f74 dropped: non-blind, see
eval/nonblind_exclusions.json). max_experiments stays 12 (the budget lever was gate-rolled-
back in cycle 1); only the user-approved HARNESS fixes change. Governance 7 files untouched.

Driven at top level (agent spawns blind solver subagents between prepare and grade, like
Phase 48/51). Grade unlocks the vault only to read the key, then re-locks (solver blind).

  python3 eval/p52_cycle2.py prepare     # 6x2 failure sessions + holdout regression sessions + guard
  python3 eval/p52_cycle2.py grade        # verifier-grade all -> conversions + holdout no-drop
"""
import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
_s = importlib.util.spec_from_file_location("p51", PROJECT_ROOT / "eval" / "p51_cycle.py")
P = importlib.util.module_from_spec(_s); _s.loader.exec_module(P)
R, verifier, ARENA, KEYS = P.R, P.verifier, P.ARENA, P.KEYS

ROOT = PROJECT_ROOT / "store" / "p52_misc"
ROOT.mkdir(parents=True, exist_ok=True)

FAILURES = ["mr_42745d", "mr_60057e", "mr_8c08a5", "mr_a5950f", "mr_ec419b", "mr_f0bf90"]
# cycle-1 verifier holdout (mr_1f8f74 excluded as non-blind; mr_30b660 is a key-audit case).
HOLDOUT = ["mr_0b0e1d", "mr_270c3b", "mr_30b660"]
HOLDOUT_BEFORE = {"mr_0b0e1d": True, "mr_270c3b": True, "mr_30b660": False}  # cycle-1 verifier verdicts

# run_id -> cid
DEV = {f"p52c2-{c}-1": c for c in FAILURES} | {f"p52c2-{c}-2": c for c in FAILURES}
HO = {f"p52c2-{c}": c for c in HOLDOUT}
ALL = DEV | HO


def _prepare(mapping):
    made = []
    for rid, cid in mapping.items():
        d = ROOT / rid
        if d.exists():
            continue
        d.mkdir(parents=True)
        (d / "session.json").write_text(json.dumps({
            "run_id": rid, "challenge_id": cid, "rep": 1,
            "challenge_dir": str(ARENA / cid), "status": "OPEN", "exp_count": 0,
            "experiments": [], "started_at": None, "config": "C1",
            "category": "misc_forensics", "prompt_pack": True,
            "image": "ctfagent-misc:0.6",
            "boundary": "plain container, --network none"}, indent=2, sort_keys=True))
        (d / "PROMPT.txt").write_text(P.c1_prompt(cid, rid))
        made.append(rid)
    guard = R.guard_prespawn(FAILURES + HOLDOUT, ROOT)
    return made, guard


def grade():
    R.unlock()
    try:
        rows = {}
        for rid, cid in ALL.items():
            hdir = ROOT / rid / "harness"
            v = verifier.verify(hdir, cid, scorer_keys_dir=KEYS) if hdir.exists() \
                else {"verdict": "NO_RUN", "solved": False}
            rows[rid] = {"cid": cid, "verdict": v["verdict"], "solved": bool(v.get("solved"))}
        R.arm_trap()
    finally:
        R.lock()
    # conversions: a failure CID converts if >=1 of its K=2 now SOLVED (verifier)
    conv = {}
    for c in FAILURES:
        s = [rows[r]["solved"] for r in (f"p52c2-{c}-1", f"p52c2-{c}-2") if r in rows]
        conv[c] = {"k": len(s), "solved": sum(s), "converted": any(s)}
    ho_after = sum(1 for c in HOLDOUT if rows.get(f"p52c2-{c}", {}).get("solved"))
    ho_before = sum(1 for v in HOLDOUT_BEFORE.values() if v)
    out = {
        "conversions": conv,
        "n_converted": sum(1 for c in conv.values() if c["converted"]),
        "holdout_before": ho_before, "holdout_after": ho_after,
        "holdout_no_strict_drop": ho_after >= ho_before,
        "rows": rows,
    }
    (ROOT / "remeasure.json").write_text(json.dumps(out, indent=1))
    return out


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "prepare":
        made, guard = _prepare(ALL)
        print(json.dumps({"prepared": made, "n": len(made), "guard_guarded": guard["guarded"],
                          "image": "ctfagent-misc:0.6", "budget": "12 exp / 2400 s / 300 s-exp (p52c2)"}, indent=1))
    elif cmd == "grade":
        print(json.dumps(grade(), indent=1))
    else:
        raise SystemExit(__doc__)
