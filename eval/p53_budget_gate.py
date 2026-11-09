"""Phase 53 AUTO budget-gate (first AUTO-adoption test). Lever = misc difficulty-band cap
max_experiments 12 -> 20 (NOT global; cost-bounded). Targets = the genuine budget-bucket
cycle-1/2 failures that REACHED the final step and died at exactly 12 experiments:
mr_8c08a5 (reconstructed PPTX; needed 1 exp to detag <a:t> runs + regex) and mr_a5950f
(decrypted flag.png; needed 1 exp to render the banner). Excluded: mr_ec419b (approach:
unsolved glyph OCR), mr_42745d (dead-end: AES key not derivable) -> stay in needs-queue.

before @cap12/0.6 is REUSED from store/p52_misc/remeasure.json (identical harness, this
session: both targets 0/2, holdout mr_0b0e1d+mr_270c3b 2/2). Only AFTER @cap20 is run fresh,
plus holdout AFTER @cap20 for the no-drop guard. Same image 0.6, same persist/pids/300s --
the ONLY difference vs before is the experiment budget.

Blind: solver runs are blind (vault 0o0); grade unlocks only to read keys then re-locks.
Governance 7 files untouched. The agent spawns the AFTER solver subagents; the USER runs the
single batch grade (the classifier blocks an agent-issued vault unlock):

  python3 eval/p53_budget_gate.py prepare    # p53ga after sessions (targets x2 + holdout x2) + guard
  python3 eval/p53_budget_gate.py grade      # USER: unlock -> verify after+holdout -> relock -> result.json
  python3 eval/p53_budget_gate.py decide     # flip AND holdout no-drop -> adopt | rollback (hash-verified)
"""
import importlib.util, hashlib, json, re, sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
_s = importlib.util.spec_from_file_location("p51", PROJECT_ROOT / "eval" / "p51_cycle.py")
P = importlib.util.module_from_spec(_s); _s.loader.exec_module(P)
R, verifier, ARENA, KEYS = P.R, P.verifier, P.ARENA, P.KEYS

ROOT = PROJECT_ROOT / "store" / "p53_gate"
ROOT.mkdir(parents=True, exist_ok=True)
LEDGER = ROOT / "gate_ledger.json"
MISC_CLI = PROJECT_ROOT / "arena" / "misc_cli.py"
P52_REMEASURE = PROJECT_ROOT / "store" / "p52_misc" / "remeasure.json"

TARGETS = ["mr_8c08a5", "mr_a5950f"]
HOLDOUT = ["mr_0b0e1d", "mr_270c3b"]            # mr_1f8f74 + mr_30b660 excluded (non-blind)
AFTER = {f"p53ga-{c}-1": c for c in TARGETS} | {f"p53ga-{c}-2": c for c in TARGETS} \
        | {f"p53ga-{c}": c for c in HOLDOUT}


def _prepare():
    made = []
    for rid, cid in AFTER.items():
        d = ROOT / rid
        if d.exists():
            continue
        d.mkdir(parents=True)
        (d / "session.json").write_text(json.dumps({
            "run_id": rid, "challenge_id": cid, "rep": 1,
            "challenge_dir": str(ARENA / cid), "status": "OPEN", "exp_count": 0,
            "experiments": [], "started_at": None, "config": "C1",
            "category": "misc_forensics", "prompt_pack": True, "image": "ctfagent-misc:0.6",
            "boundary": "plain container, --network none"}, indent=2, sort_keys=True))
        (d / "PROMPT.txt").write_text(P.c1_prompt(cid, rid))
        made.append(rid)
    guard = R.guard_prespawn(TARGETS + HOLDOUT, ROOT)
    return made, guard


def grade():
    R.unlock()
    try:
        rows = {}
        for rid, cid in AFTER.items():
            hdir = ROOT / rid / "harness"
            v = verifier.verify(hdir, cid, scorer_keys_dir=KEYS) if hdir.exists() \
                else {"verdict": "NO_RUN", "solved": False}
            rows[rid] = {"cid": cid, "verdict": v["verdict"], "solved": bool(v.get("solved"))}
        R.arm_trap()
    finally:
        R.lock()
    after = {c: {"k": 2, "solved": sum(rows[f"p53ga-{c}-{k}"]["solved"] for k in (1, 2)),
                 "runs": {k: rows[f"p53ga-{c}-{k}"] for k in (1, 2)}} for c in TARGETS}
    ho_after = sum(1 for c in HOLDOUT if rows[f"p53ga-{c}"]["solved"])
    out = {"after_cap20": after, "holdout_after": ho_after,
           "holdout_cids": HOLDOUT, "rows": rows}
    led = json.loads(LEDGER.read_text()); led["grade"] = out; LEDGER.write_text(json.dumps(led, indent=1))
    (ROOT / "result.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({"after_cap20": {c: f'{after[c]["solved"]}/2' for c in TARGETS},
                      "holdout_after": f"{ho_after}/{len(HOLDOUT)}"}, indent=1))


def _before():
    """before @cap12 reused from p52c2 remeasure: targets 0/2 each, holdout solved count."""
    rm = json.loads(P52_REMEASURE.read_text())
    tgt = {c: rm["conversions"][c]["solved"] for c in TARGETS}      # solved count at cap12 (expect 0)
    ho = sum(1 for c in HOLDOUT if rm["rows"].get(f"p52c2-{c}", {}).get("solved"))
    return tgt, ho


def decide():
    led = json.loads(LEDGER.read_text()); g = led["grade"]
    before_t, before_ho = _before()
    # flip: ANY target clearly flips 0/2 -> >=2/2 at cap20
    flips = {c: (before_t[c] == 0 and g["after_cap20"][c]["solved"] >= 2) for c in TARGETS}
    flip = any(flips.values())
    no_drop = g["holdout_after"] >= before_ho
    adopt = flip and no_drop
    cur = hashlib.sha256(MISC_CLI.read_bytes()).hexdigest()
    out = {"flip": flip, "flips": flips,
           "target_detail": {c: f'{before_t[c]}/2 -> {g["after_cap20"][c]["solved"]}/2' for c in TARGETS},
           "holdout_no_drop": no_drop, "holdout_detail": f'{before_ho} -> {g["holdout_after"]}',
           "decision": "adopt" if adopt else "rollback"}
    if not adopt:
        s0 = led["misc_cli_sha256_S0"]
        text = MISC_CLI.read_text()
        text2 = re.sub(r'elif _RUN_ID\.startswith\("p53ga"\):.*?elif _RUN_ID\.startswith\("p52c2"\):',
                       'elif _RUN_ID.startswith("p52c2"):', text, flags=re.S)
        MISC_CLI.write_text(text2)
        now = hashlib.sha256(MISC_CLI.read_bytes()).hexdigest()
        out["rollback_verified"] = (now == s0)
        out["misc_cli_sha256_now"], out["misc_cli_sha256_S0"] = now, s0
        if now != s0:
            out["ROLLBACK_ERROR"] = "misc_cli.py did not restore to S0"
    else:
        out["note"] = ("ADOPT (first AUTO adoption): cap raised for the misc hard/multi-step band. "
                       "COST TRADEOFF: up to +8 experiments/run on this band (12->20) = more container "
                       "time per hard challenge; applied to the band only, NOT global.")
        out["auto_applied"] = 1
        out["misc_cli_sha256_now"] = cur
    out.setdefault("auto_applied", 0)
    led["decision"] = out; LEDGER.write_text(json.dumps(led, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "prepare":
        made, guard = _prepare()
        print(json.dumps({"prepared": made, "n": len(made), "guard_guarded": guard["guarded"],
                          "targets": TARGETS, "holdout": HOLDOUT,
                          "before_reused_from": "store/p52_misc/remeasure.json"}, indent=1))
    elif cmd == "grade":
        grade()
    elif cmd == "decide":
        decide()
    else:
        raise SystemExit(__doc__)
