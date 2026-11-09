"""Phase 51 AUTO-gate driver (budget-bucket lever: misc max_experiments 12 -> 20).

ONE lever, one candidate (mr_42745d, bucket=budget). before/after BOTH on ctfagent-misc:0.5,
the ONLY difference being the experiment budget (prefix p51gb=12 vs p51ga=20; per-exp 90s
UNCHANGED, wall raised 1200->1800 only so the extra experiments can actually run). Noise-aware
flip: adopt the dev-target flip only if before 0/2 -> after >=2/2 ("unambiguous"). Holdout(4)
must show NO strict drop. Rollback (non-adopt) restores arena/misc_cli.py to its pre-gate bytes,
sha256-verified against store/p51_gate/gate_ledger.json:misc_cli_sha256_S0.

Blindness: gate runs are blind (vault stays chmod-0; grade only unlocks to read the key then
re-locks). Governance 7 files untouched. Driven at top level: the agent spawns the blind solver
subagents between `prepare` and `grade`, exactly like Phase 48.

  python3 eval/p51_gate.py prepare_before     # 2x target + 4x holdout sessions at budget 12
  python3 eval/p51_gate.py grade_before
  python3 eval/p51_gate.py prepare_after       # 2x target + 4x holdout sessions at budget 20
  python3 eval/p51_gate.py grade_after
  python3 eval/p51_gate.py decide              # flip + holdout-no-drop -> adopt|rollback (hash)
"""
import importlib.util
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
_spec = importlib.util.spec_from_file_location("p51_cycle", PROJECT_ROOT / "eval" / "p51_cycle.py")
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)
R, verifier, ARENA, KEYS = P.R, P.verifier, P.ARENA, P.KEYS

GATE_ROOT = PROJECT_ROOT / "store" / "p51_gate"
GATE_ROOT.mkdir(parents=True, exist_ok=True)
LEDGER = GATE_ROOT / "gate_ledger.json"
MISC_CLI = PROJECT_ROOT / "arena" / "misc_cli.py"

TARGET = "mr_42745d"
HOLDOUT = ["mr_0b0e1d", "mr_1f8f74", "mr_270c3b", "mr_30b660"]
# run_id -> cid. before = p51gb (budget 12), after = p51ga (budget 20).
BEFORE = {f"p51gb-{TARGET}-1": TARGET, f"p51gb-{TARGET}-2": TARGET,
          **{f"p51gb-{c}": c for c in HOLDOUT}}
AFTER = {f"p51ga-{TARGET}-1": TARGET, f"p51ga-{TARGET}-2": TARGET,
         **{f"p51ga-{c}": c for c in HOLDOUT}}


def _prepare(mapping):
    made = []
    for rid, cid in mapping.items():
        d = GATE_ROOT / rid
        if d.exists():
            continue
        d.mkdir(parents=True)
        (d / "session.json").write_text(json.dumps({
            "run_id": rid, "challenge_id": cid, "rep": 1,
            "challenge_dir": str(ARENA / cid), "status": "OPEN", "exp_count": 0,
            "experiments": [], "started_at": None, "config": "C1",
            "category": "misc_forensics", "prompt_pack": True,
            "image": "ctfagent-misc:0.5",
            "boundary": "plain container, --network none"}, indent=2, sort_keys=True))
        (d / "PROMPT.txt").write_text(P.c1_prompt(cid, rid))
        made.append(rid)
    # Blind guard for HOLDOUT cids only (mr_42745d is already guarded under store/p51_misc).
    guard = R.guard_prespawn(HOLDOUT, GATE_ROOT)
    return made, guard


def _grade(mapping):
    R.unlock()
    try:
        rows = {}
        for rid, cid in mapping.items():
            hdir = GATE_ROOT / rid / "harness"
            v = verifier.verify(hdir, cid, scorer_keys_dir=KEYS) if hdir.exists() \
                else {"verdict": "NO_RUN", "solved": False}
            rows[rid] = {"cid": cid, "verdict": v["verdict"], "solved": bool(v.get("solved"))}
        R.arm_trap()
    finally:
        R.lock()
    return rows


def _target_score(rows):
    t = [r["solved"] for rid, r in rows.items() if r["cid"] == TARGET]
    return sum(t), len(t)


def _holdout_score(rows):
    h = [r["solved"] for rid, r in rows.items() if r["cid"] in HOLDOUT]
    return sum(h), len(h)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "prepare_before":
        made, guard = _prepare(BEFORE)
        print(json.dumps({"prepared": made, "guard": guard, "budget": "12 (p51gb)"}, indent=1))
    elif cmd == "prepare_after":
        made, guard = _prepare(AFTER)
        print(json.dumps({"prepared": made, "guard": guard, "budget": "20 (p51ga)"}, indent=1))
    elif cmd == "grade_before":
        rows = _grade(BEFORE)
        s, n = _target_score(rows)
        hs, hn = _holdout_score(rows)
        led = json.loads(LEDGER.read_text())
        led["before"] = {"rows": rows, "target_solved": s, "target_n": n,
                         "holdout_solved": hs, "holdout_n": hn}
        LEDGER.write_text(json.dumps(led, indent=1))
        print(json.dumps({"target": f"{s}/{n}", "holdout": f"{hs}/{hn}", "rows": rows}, indent=1))
    elif cmd == "grade_after":
        rows = _grade(AFTER)
        s, n = _target_score(rows)
        hs, hn = _holdout_score(rows)
        led = json.loads(LEDGER.read_text())
        led["after"] = {"rows": rows, "target_solved": s, "target_n": n,
                        "holdout_solved": hs, "holdout_n": hn}
        LEDGER.write_text(json.dumps(led, indent=1))
        print(json.dumps({"target": f"{s}/{n}", "holdout": f"{hs}/{hn}", "rows": rows}, indent=1))
    elif cmd == "decide":
        led = json.loads(LEDGER.read_text())
        b, a = led["before"], led["after"]
        flip = (b["target_solved"] == 0) and (a["target_solved"] >= 2)   # 0/2 -> >=2/2
        no_drop = a["holdout_solved"] >= b["holdout_solved"]             # no strict drop
        adopt = flip and no_drop
        cur = hashlib.sha256(MISC_CLI.read_bytes()).hexdigest()
        out = {"flip": flip, "flip_detail": f"{b['target_solved']}/{b['target_n']} -> {a['target_solved']}/{a['target_n']}",
               "holdout_no_drop": no_drop, "holdout_detail": f"{b['holdout_solved']}/{b['holdout_n']} -> {a['holdout_solved']}/{a['holdout_n']}",
               "decision": "adopt" if adopt else "rollback"}
        if not adopt:
            # Atomic hash-verified rollback: restore misc_cli.py to S0 (remove gate prefixes).
            s0 = led["misc_cli_sha256_S0"]
            # reconstruct S0 by removing the two gate branches we added
            text = MISC_CLI.read_text()
            import re
            text2 = re.sub(r'elif _RUN_ID\.startswith\("p51gb"\):.*?elif _RUN_ID\.startswith\("p45ms"\)',
                           'elif _RUN_ID.startswith("p45ms")', text, flags=re.S)
            MISC_CLI.write_text(text2)
            now = hashlib.sha256(MISC_CLI.read_bytes()).hexdigest()
            out["rollback_verified"] = (now == s0)
            out["misc_cli_sha256_now"] = now
            out["misc_cli_sha256_S0"] = s0
            if now != s0:
                out["ROLLBACK_ERROR"] = "misc_cli.py did not restore to S0 byte-identically"
        else:
            out["note"] = "ADOPT: gate prefixes kept as measurement record; standing budget raise is a SEPARATE commit (deferred to user)."
            out["misc_cli_sha256_now"] = cur
        led["decision"] = out
        LEDGER.write_text(json.dumps(led, indent=1))
        print(json.dumps(out, indent=1))
    else:
        raise SystemExit(__doc__)
