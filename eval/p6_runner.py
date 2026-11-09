"""Phase 6 runner: C0 vs C1 one-shot (1 container experiment) on the SAME 36 instances.

  python3 eval/p6_runner.py <c0|c1> prepare <rep>
  python3 eval/p6_runner.py <c0|c1> verify <rep> <transcript.jsonl>...
  python3 eval/p6_runner.py <c0|c1> report | lock | unlock | lockstate
  python3 eval/p6_runner.py compare            # paired C0 vs C1 -> store/p6_compare.{json,md}

Reuses eval/c0b_runner.py (lock, atime trap, transcript audit, verifier, aggregation)
with per-config settings. While one config's batch runs, the lock also covers the
OTHER config's whole store, the earlier Phase 5/5b stores, vault/, and eval/packs/.
Only one config may hold the lock at a time.
"""
import importlib.util
import json
import math
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
os.environ.pop("P5B_SET", None)
_spec = importlib.util.spec_from_file_location("c0b_runner", PROJECT_ROOT / "eval" / "c0b_runner.py")
R = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R)
c0r = R.c0r

BUDGET = {"max_experiments": 1, "wall_s": 1200, "exp_timeout_s": 30}
CONFIGS = {
    "c0": {"config": "C0", "loop": "single ReAct", "prompt_pack": False,
           "experience_store": False, "attempts_per_run": 1, "budget_experiments": 1},
    "c1": {"config": "C1", "loop": "single ReAct", "prompt_pack": "eval/packs/crypto_pack_v1.md",
           "experience_store": False, "attempts_per_run": 1, "budget_experiments": 1},
}
BASE_SECRETS = ["vault", "store/c0", "store/runs", "store/c0b", "store/c0b2", "store/p6_validate.log",
                "eval/scorer_keys", "eval/make_dev_set.py", "eval/make_dev_challenge.py", "eval/packs"]


def configure(cfg):
    other = "c1" if cfg == "c0" else "c0"
    R.ROOT = PROJECT_ROOT / "store" / f"p6_{cfg}"
    R.RESULTS = R.ROOT / "results.jsonl"
    R.LOCKFILE = R.ROOT / "lock.json"
    R.TRAPFILE = R.ROOT / "trap.json"
    R.MANIFEST = R.VAULT / "manifest_p6.json"
    R.RUN_PREFIX = f"p6{cfg}"
    R.STATIC_SECRETS = BASE_SECRETS + [f"store/p6_{other}"]
    R.C0_CONFIG = dict(CONFIGS[cfg])
    R.BUDGET = BUDGET
    R.CLI_RE = re.compile(rf"^cd ~/ctf_agent_v3 && python3 arena/p6_cli\.py (p6{cfg}-r(\d+)-p5b_[0-9a-f]{{6}}) "
                          r"(info|exp|report|give_up|status)\b(.*)$")
    R.ROOT.mkdir(parents=True, exist_ok=True)
    _orig_lock = R.lock

    def guarded_lock():
        p = PROJECT_ROOT / "store" / f"p6_{other}" / "lock.json"
        try:
            held = p.exists()
        except PermissionError:
            held = True
        if held and not R.LOCKFILE.exists():
            raise SystemExit(f"p6_{other} holds the lock; run `p6_runner.py {other} unlock` first")
        _orig_lock()
    R.lock = guarded_lock


# ---- paired comparison --------------------------------------------------------

def _mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return round(min(1.0, 2 * tail), 4)


def compare():
    rows = {}
    for cfg in ("c0", "c1"):
        p = PROJECT_ROOT / "store" / f"p6_{cfg}" / "results.jsonl"
        rows[cfg] = {r["challenge_id"]: r for r in c0r._read_jsonl(p)}
    common = sorted(set(rows["c0"]) & set(rows["c1"]))
    solved = {cfg: {cid: rows[cfg][cid]["outcome"] == "SOLVED" for cid in common} for cfg in rows}
    both = sum(solved["c0"][c] and solved["c1"][c] for c in common)
    c0_only = sum(solved["c0"][c] and not solved["c1"][c] for c in common)
    c1_only = sum(solved["c1"][c] and not solved["c0"][c] for c in common)
    neither = len(common) - both - c0_only - c1_only

    def rate(cfg, pred=lambda r: True):
        return c0r._rate([rows[cfg][c] for c in common if pred(rows[cfg][c])])

    def group(key):
        vals = sorted({rows["c0"][c][key] for c in common})
        return {v: {cfg: rate(cfg, lambda r, v=v: r[key] == v) for cfg in ("c0", "c1")} for v in vals}
    per_type = {}
    for st in sorted({rows["c0"][c]["subtype"] for c in common}):
        ids = [c for c in common if rows["c0"][c]["subtype"] == st]
        per_type[st] = {"difficulty": rows["c0"][ids[0]]["difficulty"],
                        **{cfg: f"{sum(solved[cfg][c] for c in ids)}/{len(ids)}" for cfg in ("c0", "c1")}}
    reports = {}
    for cfg in ("c0", "c1"):
        rp = PROJECT_ROOT / "store" / f"p6_{cfg}" / "report.json"
        reports[cfg] = json.loads(rp.read_text()) if rp.exists() else {}

    def eff(cfg):
        r = reports[cfg]
        return {k: r.get(k) for k in ("tool_call_validity", "wall_s_per_run", "flag_without_solution",
                                      "outcomes", "failure_kinds_non_solved", "non_container_executions",
                                      "blindness")} | {
            "tokens_components_per_agent": (r.get("consumption_proxy") or {}).get("tokens_components_per_agent")}
    # re-audit transcripts with the current (quote-aware) auditor; results.jsonl keeps the verify-time flag
    reaudit = {}
    for cfg in ("c0", "c1"):
        R.CLI_RE = re.compile(rf"^cd ~/ctf_agent_v3 && python3 arena/p6_cli\.py (p6{cfg}-r(\d+)-p5b_[0-9a-f]{{6}}) "
                              r"(info|exp|report|give_up|status)\b(.*)$")
        for tf in sorted((PROJECT_ROOT / "store" / f"p6_{cfg}").glob("transcripts_r*.txt")):
            rep_no = int(tf.stem.split("_r")[1])
            for line in tf.read_text().split():
                if Path(line).exists():
                    a = R.audit_transcript(line, rep_no)
                    for rid in a["run_ids"]:
                        reaudit[rid] = {"clean": a["clean"], "nonconforming": a["nonconforming"]}
    audit = {cfg: {"verify_time_clean": sum(1 for c in common if rows[cfg][c]["transcript_clean"]),
                   "reaudit_clean": sum(1 for c in common if reaudit.get(rows[cfg][c]["run_id"], {}).get("clean")),
                   "reaudit_nonconforming": {rows[cfg][c]["run_id"]: reaudit[rows[cfg][c]["run_id"]]["nonconforming"]
                                             for c in common if rows[cfg][c]["run_id"] in reaudit
                                             and not reaudit[rows[cfg][c]["run_id"]]["clean"]}}
             for cfg in ("c0", "c1")}
    # sensitivity: drop pairs where either config executed no experiment (e.g. response blocked before exp)
    no_exp = {cfg: sorted(c for c in common if rows[cfg][c]["n_exp"] == 0) for cfg in ("c0", "c1")}
    kept = [c for c in common if rows["c0"][c]["n_exp"] > 0 and rows["c1"][c]["n_exp"] > 0]
    s_b = sum(solved["c0"][c] and not solved["c1"][c] for c in kept)
    s_c = sum(solved["c1"][c] and not solved["c0"][c] for c in kept)
    sensitivity = {"excluded_pairs": len(common) - len(kept), "kept_pairs": len(kept),
                   "no_experiment_runs": {cfg: [rows[cfg][c]["subtype"] + ":" + c for c in no_exp[cfg]] for cfg in no_exp},
                   "c0": c0r._rate([rows["c0"][c] for c in kept]), "c1": c0r._rate([rows["c1"][c] for c in kept]),
                   "c0_only": s_b, "c1_only": s_c, "mcnemar_exact_p": _mcnemar_exact(s_b, s_c)}
    out = {
        "design": {"instances_paired": len(common), "runs": 2 * len(common), "budget": BUDGET,
                   "configs": CONFIGS, "note": "small sample; provisional; pretraining contamination likely; "
                                               "pack author had seen the dev-set types"},
        "solve_rate": {"overall": {cfg: rate(cfg) for cfg in ("c0", "c1")},
                       "by_difficulty": group("difficulty"), "by_family": group("family")},
        "paired": {"both": both, "c0_only": c0_only, "c1_only": c1_only, "neither": neither,
                   "diff_c1_minus_c0": round((c1_only - c0_only) / len(common), 3) if common else None,
                   "mcnemar_exact_p": _mcnemar_exact(c0_only, c1_only)},
        "headroom_c0": {"ceiling": rate("c0")["rate"] == 1.0, "floor": rate("c0")["rate"] == 0.0},
        "variability_per_type": per_type,
        "sensitivity_excluding_no_experiment_pairs": sensitivity,
        "transcript_audit": audit,
        "efficiency": {cfg: eff(cfg) for cfg in ("c0", "c1")},
    }
    (PROJECT_ROOT / "store" / "p6_compare.json").write_text(json.dumps(out, indent=2) + "\n")
    (PROJECT_ROOT / "store" / "p6_compare.md").write_text(_md(out))
    print(json.dumps(out, indent=2))


def _md(o):
    L = ["# Phase 6 — C0 vs C1 one-shot (auto-generated by eval/p6_runner.py)", "",
         f"Design: {o['design']['instances_paired']} paired instances x 2 configs = {o['design']['runs']} runs; "
         f"budget {o['design']['budget']}. **Small sample, provisional; contamination likely.**", "",
         "| group | C0 solved/runs (Wilson95) | C1 solved/runs (Wilson95) |", "|---|---|---|"]
    def cell(r):
        return f"{r['solved']}/{r['runs']} {r['wilson95']}"
    ov = o["solve_rate"]["overall"]
    L.append(f"| overall | {cell(ov['c0'])} | {cell(ov['c1'])} |")
    for sect in ("by_difficulty", "by_family"):
        for k, v in o["solve_rate"][sect].items():
            L.append(f"| {sect[3:]}={k} | {cell(v['c0'])} | {cell(v['c1'])} |")
    p = o["paired"]
    L += ["", f"Paired: both={p['both']} c0_only={p['c0_only']} c1_only={p['c1_only']} neither={p['neither']}; "
          f"diff(C1-C0)={p['diff_c1_minus_c0']}; McNemar exact p={p['mcnemar_exact_p']}",
          f"C0 headroom: {o['headroom_c0']}", "", "| type | diff | C0 | C1 |", "|---|---|---|---|"]
    for st, v in o["variability_per_type"].items():
        L.append(f"| {st} | {v['difficulty']} | {v['c0']} | {v['c1']} |")
    sv = o["sensitivity_excluding_no_experiment_pairs"]
    L += ["", f"Sensitivity (drop pairs where either config ran 0 experiments): kept {sv['kept_pairs']}, "
          f"C0 {cell(sv['c0'])}, C1 {cell(sv['c1'])}, c0_only={sv['c0_only']} c1_only={sv['c1_only']}, "
          f"McNemar p={sv['mcnemar_exact_p']}", f"No-experiment runs: {sv['no_experiment_runs']}",
          f"Transcript audit: {json.dumps(o['transcript_audit'])}"]
    L += ["", "## Efficiency / integrity", ""] + [f"- {cfg}: {json.dumps(v)}" for cfg, v in o["efficiency"].items()]
    return "\n".join(L) + "\n"


def main(argv):
    if argv == ["compare"]:
        compare()
        return 0
    if len(argv) < 2 or argv[0] not in CONFIGS:
        print(__doc__, file=sys.stderr)
        return 2
    configure(argv[0])
    return R.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
