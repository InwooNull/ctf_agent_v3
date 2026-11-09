"""Phase 48 — growth decision test (misc:0.4). Thin prepare/grade helpers; the gate is
driven at top level (agent spawns between stages). Reuses eval/p45_misc_growth.py for the
C1 prompt, signal extraction, lock/trap, verifier.

ATTRIBUTION CONTROL (user-mandated): a gate candidate's BEFORE-K2 baseline is measured
FRESH on misc:0.4 this phase (never reused from run #1's 0.3 image), on the SAME image as
AFTER — so a flip is attributable to the knowledge note, not the 0.4 compiler. Reuse of
run-#1 diagnoses is for BUCKET CLASSIFICATION / candidate selection only, never baseline.

  python3 eval/p48_grow.py prepare <run_id>:<cid> [...]     # create sessions+prompts, lock, trap
  python3 eval/p48_grow.py grade   <run_id>:<cid> [...]     # unlock->verify->relock -> JSON rows
"""
import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
_spec = importlib.util.spec_from_file_location("p45", PROJECT_ROOT / "eval" / "p45_misc_growth.py")
P45 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P45)
R, c0r, verifier = P45.R, P45.c0r, P45.verifier
ROOT, ARENA, KEYS = P45.ROOT, P45.ARENA, P45.KEYS


def _pairs(argv):
    out = []
    for a in argv:
        rid, cid = a.split(":")
        out.append((rid, cid))
    return out


def prepare(pairs):
    R.unlock()
    try:
        made = []
        for rid, cid in pairs:
            d = ROOT / rid
            if d.exists():
                raise SystemExit(f"{d} exists; refusing to overwrite")
            d.mkdir(parents=True)
            (d / "session.json").write_text(json.dumps({
                "run_id": rid, "challenge_id": cid, "rep": 1,
                "challenge_dir": str(ARENA / cid), "status": "OPEN", "exp_count": 0,
                "experiments": [], "started_at": None, "config": "C1-p48",
                "prompt_pack": True, "image": P45.IMAGE}, indent=2, sort_keys=True))
            (d / "PROMPT.txt").write_text(P45.c1_prompt(cid, rid))   # built from CURRENT skills
            made.append(rid)
        n = R.arm_trap()
    finally:
        R.lock()
    print(json.dumps({"prepared": made, "trap_files": n, "locked": R.LOCKFILE.exists()}, indent=1))


def grade(pairs):
    R.unlock()
    try:
        trap_hits = R.check_trap()
        rows = []
        for rid, cid in pairs:
            d = ROOT / rid
            sess = json.loads((d / "session.json").read_text())
            hdir = d / "harness"
            v = verifier.verify(hdir, cid, scorer_keys_dir=KEYS) if hdir.exists() else {"verdict": "NO_RUN", "solved": False}
            exps = sess.get("experiments", [])
            outcome, kind = c0r._classify(sess, v, exps)
            sig = P45.extract_signals(sess, v["verdict"], P45._transcript_text(d))
            rows.append({"run_id": rid, "cid": cid, "verdict": v["verdict"], "solved": bool(v.get("solved")),
                         "outcome": outcome, "failure_kind": kind, "signals": sig})
        R.arm_trap()
    finally:
        R.lock()
    print(json.dumps({"trap_hits": trap_hits, "rows": rows}, indent=1))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "prepare":
        prepare(_pairs(sys.argv[2:]))
    elif cmd == "grade":
        grade(_pairs(sys.argv[2:]))
    else:
        raise SystemExit(__doc__)
