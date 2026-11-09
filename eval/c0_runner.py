"""C0 baseline runner: prepare sessions, audit blindness, verify, aggregate.

The solver sessions themselves (one fresh LLM agent per run, C0 = single ReAct
loop, no prompt pack, no experience store, 1 trajectory per run) drive
eval/c0_cli.py. This runner owns everything else, and every number in the
report is computed here from the on-disk run records — nothing is hand-entered.

  python3 eval/c0_runner.py prepare <rep>     # sessions c0-<cid>-r<rep> for all 8 challenges + arm trap
  python3 eval/c0_runner.py verify  <rep>     # audit trap -> verifier -> results.jsonl -> re-arm
  python3 eval/c0_runner.py report            # aggregate results.jsonl -> report.json / report.md

Blindness audit (tamper-evident, not preventive): before a batch, every file in
TRAP_GLOBS gets atime set to a sentinel older than its mtime. On this relatime
ext4 mount any content read then bumps atime (stat/ls do not). `verify` checks
the sentinels BEFORE the verifier itself reads the scorer keys.
"""
import json
import math
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from solver import verifier  # noqa: E402

EVAL = PROJECT_ROOT / "eval"
DATASET = EVAL / "datasets" / "dev_p5"
MANIFEST = DATASET / "manifest.json"
C0_ROOT = PROJECT_ROOT / "store" / "c0"
RESULTS = C0_ROOT / "results.jsonl"
TRAP_STATE = C0_ROOT / "trap.json"
SENTINEL_ATIME = 1_000_000_000.0
REPS = 3

C0_CONFIG = {"config": "C0", "loop": "single ReAct", "prompt_pack": False,
             "experience_store": False, "attempts_per_run": 1}


def _manifest():
    return json.loads(MANIFEST.read_text())


def run_id_for(cid, rep):
    return f"c0-{cid}-r{rep}"


def _trap_targets(exclude_reps=()):
    """Files a blind solver must never read: answer keys, generators, the
    type manifest, Phase 4 solutions, and finished C0 runs of earlier reps."""
    paths = list((EVAL / "scorer_keys").glob("*.json"))
    paths += [EVAL / "make_dev_set.py", EVAL / "make_dev_challenge.py", MANIFEST]
    paths += [p for p in (PROJECT_ROOT / "store" / "runs").rglob("*") if p.is_file()]
    for d in C0_ROOT.glob("c0-*-r*"):
        rep = int(d.name.rsplit("-r", 1)[1])
        if rep in exclude_reps:
            continue
        paths += [p for p in d.rglob("*") if p.is_file()]
    return sorted(set(p for p in paths if p.exists()))


def arm_trap(exclude_reps=()):
    armed = {}
    for p in _trap_targets(exclude_reps):
        st = p.stat()
        os.utime(p, (SENTINEL_ATIME, max(st.st_mtime, time.time())))
        armed[str(p.relative_to(PROJECT_ROOT))] = SENTINEL_ATIME
    TRAP_STATE.write_text(json.dumps({"armed_at": time.time(), "files": armed}, indent=1))
    return len(armed)


def check_trap():
    """Return the trapped files whose content was read since arming."""
    if not TRAP_STATE.exists():
        return ["<trap never armed>"]
    state = json.loads(TRAP_STATE.read_text())
    hit = []
    for rel, sentinel in state["files"].items():
        p = PROJECT_ROOT / rel
        if p.exists() and p.stat().st_atime != sentinel:
            hit.append(rel)
    return hit


def prepare(rep):
    C0_ROOT.mkdir(parents=True, exist_ok=True)
    made = []
    for m in _manifest():
        rid = run_id_for(m["id"], rep)
        d = C0_ROOT / rid
        if d.exists():
            raise SystemExit(f"{d} already exists; refusing to reuse a run dir")
        d.mkdir(parents=True)
        sess = {"run_id": rid, "challenge_id": m["id"], "rep": rep,
                "challenge_dir": str(DATASET / m["id"]), "status": "OPEN",
                "exp_count": 0, "experiments": [], "started_at": None, **C0_CONFIG}
        (d / "session.json").write_text(json.dumps(sess, indent=2, sort_keys=True))
        made.append(rid)
    n = arm_trap(exclude_reps=(rep,))
    print(json.dumps({"rep": rep, "runs": made, "trap_files": n}))


def _read_jsonl(p):
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def _classify(sess, verdict, exps):
    status = sess["status"]
    if verdict["verdict"] == verifier.SOLVED:
        return "SOLVED", None
    if verdict["verdict"] == verifier.FLAG_WITHOUT_SOLUTION:
        outcome = "FLAG_WITHOUT_SOLUTION"
    elif status == "REPORTED":
        outcome = "WRONG_FLAG"
    elif status in ("GIVE_UP", "BUDGET_EXHAUSTED"):
        outcome = status
    else:
        outcome = "NO_TERMINAL"            # agent stopped without report/give_up
    # Failure kind (mechanical rule, documented in the report):
    #   tool_failure     : no experiment ran ok, or < half of experiments ran ok
    #   analysis_failure : tooling mostly worked, the reasoning did not reach the flag
    n_ok = sum(1 for e in exps if e["status"] == "ok")
    if not exps or n_ok == 0 or n_ok < len(exps) / 2:
        kind = "tool_failure"
    else:
        kind = "analysis_failure"
    return outcome, kind


def verify_rep(rep):
    trap_hits = check_trap()            # BEFORE the verifier reads any key
    man = {m["id"]: m for m in _manifest()}
    done = {r["run_id"] for r in _read_jsonl(RESULTS)}
    out = []
    for cid, m in man.items():
        rid = run_id_for(cid, rep)
        if rid in done:
            raise SystemExit(f"{rid} already verified")
        d = C0_ROOT / rid
        sess = json.loads((d / "session.json").read_text())
        hdir = d / "harness"
        v = verifier.verify(hdir, cid)
        exps = sess["experiments"]
        calls = _read_jsonl(d / "c0_calls.jsonl")
        outcome, kind = _classify(sess, v, exps)
        end = sess.get("ended_at") or (calls[-1]["t"] if calls else None)
        rec = {
            "run_id": rid, "challenge_id": cid, "rep": rep,
            "family": m["family"], "subtype": m["subtype"], "difficulty": m["difficulty"],
            "verdict": v["verdict"], "outcome": outcome, "failure_kind": kind,
            "session_status": sess["status"],
            "give_up": sess.get("give_up"),
            "n_exp": len(exps),
            "n_exp_ok": sum(1 for e in exps if e["status"] == "ok"),
            "n_exp_error": sum(1 for e in exps if e["status"] == "error"),
            "n_exp_timeout": sum(1 for e in exps if e["status"] == "timeout"),
            "n_exp_aborted": sum(1 for e in exps if e["status"] == "aborted"),
            "n_exp_cached": sum(1 for e in exps if e.get("cached")),
            "non_container_exps": sum(1 for e in exps
                                      if e["profile"] != "container" and not e.get("cached")),
            "n_cli_calls": len(calls),
            "n_cli_errors": sum(1 for c in calls if not c["ok"]),
            "wall_s": round(end - sess["started_at"], 1) if (end and sess.get("started_at")) else None,
            "evidence_exp_id": v.get("evidence_exp_id"),
            "batch_trap_hits": trap_hits,
            **C0_CONFIG,
        }
        out.append(rec)
    with open(RESULTS, "a", encoding="utf-8") as f:
        for rec in out:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
    arm_trap()                          # re-arm including this rep's finished runs
    print(json.dumps([{k: r[k] for k in ("run_id", "outcome", "n_exp")} for r in out]
                     + [{"trap_hits": trap_hits}], indent=1))


# ---- aggregation ------------------------------------------------------------

def _wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (round(max(0.0, c - h), 3), round(min(1.0, c + h), 3))


def _rate(rows):
    k = sum(1 for r in rows if r["outcome"] == "SOLVED")
    n = len(rows)
    return {"solved": k, "runs": n, "rate": round(k / n, 3) if n else None, "wilson95": _wilson(k, n)}


def _stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return {"mean": round(sum(xs) / len(xs), 2), "min": min(xs), "max": max(xs), "n": len(xs)}


def aggregate():
    rows = _read_jsonl(RESULTS)
    by = lambda key: {k: _rate([r for r in rows if r[key] == k])
                      for k in sorted({r[key] for r in rows})}
    per_ch = {}
    for cid in sorted({r["challenge_id"] for r in rows}):
        rr = sorted([r for r in rows if r["challenge_id"] == cid], key=lambda r: r["rep"])
        per_ch[cid] = {"subtype": rr[0]["subtype"], "difficulty": rr[0]["difficulty"],
                       "solved_of_reps": f"{sum(r['outcome'] == 'SOLVED' for r in rr)}/{len(rr)}",
                       "per_rep": [r["outcome"] for r in rr],
                       "n_exp_per_rep": [r["n_exp"] for r in rr]}
    tot_exp = sum(r["n_exp"] for r in rows)
    tot_ok = sum(r["n_exp_ok"] for r in rows)
    tot_calls = sum(r["n_cli_calls"] for r in rows)
    tot_call_err = sum(r["n_cli_errors"] for r in rows)
    outcomes = defaultdict(int)
    kinds = defaultdict(int)
    for r in rows:
        outcomes[r["outcome"]] += 1
        if r["failure_kind"]:
            kinds[r["failure_kind"]] += 1
    trap_hits = sorted({h for r in rows for h in r["batch_trap_hits"]})
    rep = {
        "config": C0_CONFIG,
        "budget": {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 30},
        "sample": {"challenges": len(per_ch), "reps": REPS, "runs": len(rows),
                   "note": "small sample (8 challenges x 3 reps) -> provisional"},
        "solve_rate": {"overall": _rate(rows), "by_difficulty": by("difficulty"),
                       "by_family": by("family"), "by_subtype": by("subtype")},
        "variability": per_ch,
        "experiments_per_run": _stats([r["n_exp"] for r in rows]),
        "experiments_per_solved_run": _stats([r["n_exp"] for r in rows if r["outcome"] == "SOLVED"]),
        "wall_s_per_run": _stats([r["wall_s"] for r in rows]),
        "tool_call_validity": {
            "exp_ok_over_exp": f"{tot_ok}/{tot_exp}",
            "exp_ok_rate": round(tot_ok / tot_exp, 3) if tot_exp else None,
            "cli_ok_over_calls": f"{tot_calls - tot_call_err}/{tot_calls}",
            "cli_ok_rate": round((tot_calls - tot_call_err) / tot_calls, 3) if tot_calls else None},
        "flag_without_solution": outcomes.get("FLAG_WITHOUT_SOLUTION", 0),
        "outcomes": dict(outcomes),
        "failure_kinds_non_solved": dict(kinds),
        "give_up_self_reported": [r["give_up"] for r in rows if r["give_up"]],
        "non_container_executions": sum(r["non_container_exps"] for r in rows),
        "consumption_proxy": {"agent_sessions": len(rows), "experiments": tot_exp,
                              "cli_calls": tot_calls,
                              "wall_s_total": round(sum(r["wall_s"] or 0 for r in rows), 1)},
        "blindness_audit": {"trap_hits": trap_hits, "clean": not trap_hits},
    }
    (C0_ROOT / "report.json").write_text(json.dumps(rep, indent=2) + "\n")
    (C0_ROOT / "report.md").write_text(_markdown(rep, rows))
    print(json.dumps(rep, indent=2))


def _markdown(rep, rows):
    L = ["# C0 baseline report (auto-generated by eval/c0_runner.py)", "",
         f"Config: {rep['config']}", f"Budget/run: {rep['budget']}",
         f"Sample: {rep['sample']['runs']} runs = {rep['sample']['challenges']} challenges x "
         f"{rep['sample']['reps']} reps — **small sample, provisional**", "",
         "## Solve rate (SOLVED only)", "", "| group | solved/runs | rate | Wilson 95% |", "|---|---|---|---|"]
    o = rep["solve_rate"]["overall"]
    L.append(f"| overall | {o['solved']}/{o['runs']} | {o['rate']} | {o['wilson95']} |")
    for sect in ("by_difficulty", "by_family", "by_subtype"):
        for k, v in rep["solve_rate"][sect].items():
            L.append(f"| {sect[3:]}={k} | {v['solved']}/{v['runs']} | {v['rate']} | {v['wilson95']} |")
    L += ["", "## Variability (per challenge)", "", "| challenge | subtype | diff | solved | per rep | exps |",
          "|---|---|---|---|---|---|"]
    for cid, v in rep["variability"].items():
        L.append(f"| {cid} | {v['subtype']} | {v['difficulty']} | {v['solved_of_reps']} | "
                 f"{', '.join(v['per_rep'])} | {v['n_exp_per_rep']} |")
    L += ["", "## Other metrics", "",
          f"- experiments/run: {rep['experiments_per_run']}",
          f"- experiments/solved run: {rep['experiments_per_solved_run']}",
          f"- wall s/run: {rep['wall_s_per_run']}",
          f"- tool-call validity: {rep['tool_call_validity']}",
          f"- FLAG_WITHOUT_SOLUTION: {rep['flag_without_solution']}",
          f"- outcomes: {rep['outcomes']}",
          f"- failure kinds (non-solved, mechanical rule): {rep['failure_kinds_non_solved']}",
          f"- non-container executions: {rep['non_container_executions']}",
          f"- consumption proxy: {rep['consumption_proxy']}",
          f"- blindness audit: {rep['blindness_audit']}", ""]
    return "\n".join(L)


def main(argv):
    if argv[:1] == ["prepare"] and len(argv) == 2:
        prepare(int(argv[1]))
    elif argv[:1] == ["verify"] and len(argv) == 2:
        verify_rep(int(argv[1]))
    elif argv == ["report"]:
        aggregate()
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
