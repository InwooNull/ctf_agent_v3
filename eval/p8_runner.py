"""Phase 8 runner: Reverse C0 baseline on arena/rev_instances (30 = 10 types x 3).

  python3 eval/p8_runner.py prepare <rep>                       # rep k = k-th instance of every type (10 runs)
  python3 eval/p8_runner.py verify <rep> <transcript.jsonl>...  # trap + transcript audit -> verifier -> results
  python3 eval/p8_runner.py report                              # -> store/p8_c0/report.{json,md}
  python3 eval/p8_runner.py lock | unlock | lockstate

Reuses eval/c0b_runner.py for the lock (chmod 000 on every secret path while a
batch runs), the atime trap and the quote-aware CLI-only transcript audit.
Classification (all mechanical, from on-disk records):
  SOLVED   verifier verdict SOLVED (evidence chain)
  BLOCKED  no experiment ever executed in the container (e.g. response blocked by a
           safety classifier before any `exp`) — kept apart from capability failures
  FAILED   >=1 executed experiment, not solved; sub-kind:
           self-reported give_up kind (tool -> tool_lack, impl -> implementation_bug,
           analysis -> analysis_failure); else a wrong flag reported -> analysis_failure;
           else (budget exhausted / no terminal call) implementation_bug if >=50% of
           executed experiments ended error|timeout, otherwise analysis_failure.
  FLAG_WITHOUT_SOLUTION is counted separately (must be 0).
"""
import importlib.util
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
os.environ.pop("P5B_SET", None)
_spec = importlib.util.spec_from_file_location("c0b_runner", PROJECT_ROOT / "eval" / "c0b_runner.py")
R = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R)
c0r = R.c0r
verifier = R.verifier

ROOT = PROJECT_ROOT / "store" / "p8_c0"
ARENA = PROJECT_ROOT / "arena" / "rev_instances"
MANIFEST = R.VAULT / "manifest_rev.json"
KEYS = R.VAULT / "scorer_keys_rev"
RESULTS = ROOT / "results.jsonl"
BUDGET = {"max_experiments": 8, "wall_s": 900, "exp_timeout_s": 30}
CONFIG = {"config": "C0", "category": "rev", "loop": "single ReAct", "prompt_pack": False,
          "experience_store": False, "attempts_per_run": 1, "inspect_first": "prompt + e01 not citable",
          "image": "ctfagent-rev:0.1", "r2": False}
STATIC_SECRETS = ["vault", "eval/scorer_keys", "eval/packs", "eval/make_dev_set.py", "eval/make_dev_challenge.py",
                  "store/c0", "store/runs", "store/c0b", "store/c0b2", "store/p6_c0", "store/p6_c1",
                  "store/p6_validate.log"]   # tests/fixtures: test-only, kept readable so the suite runs under the lock
REP_RE = r"p8c0-r(\d+)-r7_[0-9a-f]{6}"
BLOCK_SIGNAL = re.compile(r"usage polic|content filter|safety|blocked|refus|API Error|violat", re.I)
FLAG_RE = re.compile(r"FLAG\{[^}]*\}")

R.ROOT, R.RESULTS, R.LOCKFILE, R.TRAPFILE = ROOT, RESULTS, ROOT / "lock.json", ROOT / "trap.json"
R.STATIC_SECRETS = STATIC_SECRETS
R.CLI_RE = re.compile(r"^cd ~/ctf_agent_v3 && python3 arena/rev_cli\.py (p8c0-r(\d+)-r7_[0-9a-f]{6}) "
                      r"(info|exp|report|give_up|status)\b(.*)$")


def _manifest_reps():
    """rep k -> the k-th instance (sorted by id) of every type."""
    man = json.loads(MANIFEST.read_text())
    by_type = {}
    for cid, m in sorted(man.items()):
        by_type.setdefault(m["type"], []).append(cid)
    out = []
    for typ, ids in sorted(by_type.items()):
        for k, cid in enumerate(ids, 1):
            out.append({"id": cid, "rep": k, "subtype": typ, "difficulty": man[cid]["difficulty"]})
    return out


def run_id_for(m):
    return f"p8c0-r{m['rep']}-{m['id']}"


def prepare(rep):
    ROOT.mkdir(parents=True, exist_ok=True)
    R.unlock()
    try:
        made = []
        for m in [m for m in _manifest_reps() if m["rep"] == rep]:
            rid = run_id_for(m)
            d = ROOT / rid
            if d.exists():
                raise SystemExit(f"{d} exists")
            d.mkdir(parents=True)
            sess = {"run_id": rid, "challenge_id": m["id"], "rep": rep, "challenge_dir": str(ARENA / m["id"]),
                    "status": "OPEN", "exp_count": 0, "experiments": [], "started_at": None, **CONFIG}
            (d / "session.json").write_text(json.dumps(sess, indent=2, sort_keys=True))
            made.append(rid)
        n = R.arm_trap()
    finally:
        R.lock()
    print(json.dumps({"rep": rep, "runs": made, "trap_files": n, "locked": R.LOCKFILE.exists()}))


def _final_text(path):
    """Last assistant text of a subagent transcript (flags masked) + whether it looks like a block."""
    last, signal = "", False
    for line in open(path, encoding="utf-8"):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("message") or {}
        c = msg.get("content")
        if rec.get("type") == "assistant" and isinstance(c, list):
            txt = " ".join(b.get("text", "") for b in c if b.get("type") == "text").strip()
            if txt:
                last = txt
        if rec.get("isApiErrorMessage") or rec.get("error"):
            signal = True
    signal = signal or bool(BLOCK_SIGNAL.search(last))
    return FLAG_RE.sub("[flag]", last)[:300], signal


def classify(sess, v, executed):
    if v["verdict"] == verifier.SOLVED:
        return "SOLVED", None, None
    if v["verdict"] == verifier.FLAG_WITHOUT_SOLUTION:
        return "FAILED", "flag_without_solution", "verifier"
    if not executed:
        return "BLOCKED", None, None
    gu = sess.get("give_up")
    if gu:
        return "FAILED", {"tool": "tool_lack", "impl": "implementation_bug",
                          "analysis": "analysis_failure"}[gu["kind"]], "self_report"
    if sess.get("reported"):
        return "FAILED", "analysis_failure", "wrong_flag_reported"
    bad = sum(e["status"] in ("error", "timeout") for e in executed)
    return "FAILED", "implementation_bug" if bad * 2 >= len(executed) else "analysis_failure", "mechanical"


def build_row(m, rid, d, a, tpath, trap_hits):
    """One results row for run dir d (manifest entry m, transcript audit a / path tpath)."""
    sess = json.loads((d / "session.json").read_text())
    v = verifier.verify(d / "harness", m["id"], scorer_keys_dir=KEYS)
    exps = sess["experiments"]
    executed = [e for e in exps if e["profile"] == "container" and not e.get("cached")]
    calls = c0r._read_jsonl(d / "c0_calls.jsonl")
    bucket, kind, kind_src = classify(sess, v, executed)
    end = sess.get("ended_at") or (calls[-1]["t"] if calls else None)
    final, signal = _final_text(tpath) if tpath else ("", False)
    gu = sess.get("give_up") or {}
    return {
        "run_id": rid, "challenge_id": m["id"], "rep": m["rep"], "subtype": m["subtype"],
        "difficulty": m["difficulty"], "verdict": v["verdict"], "bucket": bucket,
        "outcome": "SOLVED" if bucket == "SOLVED" else bucket,
        "failure_kind": kind, "failure_kind_source": kind_src,
        "session_status": sess["status"], "give_up": sess.get("give_up"),
        "mentions_r2_or_decompiler": bool(re.search(r"r2|radare|rizin|ghidra|decompil", gu.get("reason", ""), re.I)),
        "n_exp": len(exps), "n_exp_executed": len(executed),
        "n_exp_ok": sum(e["status"] == "ok" for e in exps),
        "n_exp_error": sum(e["status"] == "error" for e in exps),
        "n_exp_timeout": sum(e["status"] == "timeout" for e in exps),
        "n_exp_aborted": sum(e["status"] == "aborted" for e in exps),
        "non_container_exps": sum(1 for e in exps if e["profile"] != "container" and not e.get("cached")),
        "evidence_exp_index": int(v["evidence_exp_id"].split("-e")[1][:2]) if v.get("evidence_exp_id") else None,
        "n_cli_calls": len(calls), "n_cli_errors": sum(not c["ok"] for c in calls),
        "wall_s": round(end - sess["started_at"], 1) if (end and sess.get("started_at")) else None,
        "transcript_clean": a["clean"] if a else None,
        "transcript_nonconforming": a["nonconforming"] if a else None,
        "tokens": a["tokens_breakdown"] if a else None,
        "final_text_excerpt": final, "block_signal": signal,
        "batch_trap_hits": trap_hits, **CONFIG,
    }


def verify_rep(rep, transcripts):
    R.unlock()
    try:
        trap_hits = R.check_trap()
        audits = [R.audit_transcript(t, rep) for t in transcripts]
        by_run = {rid: (a, t) for a, t in zip(audits, transcripts) for rid in a["run_ids"]}
        done = {r["run_id"] for r in c0r._read_jsonl(RESULTS)}
        out = []
        for m in [m for m in _manifest_reps() if m["rep"] == rep]:
            rid = run_id_for(m)
            if rid in done:
                raise SystemExit(f"{rid} already verified")
            a, tpath = by_run.get(rid, (None, None))
            out.append(build_row(m, rid, ROOT / rid, a, tpath, trap_hits))
        with open(RESULTS, "a", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        (ROOT / f"audit_r{rep}.json").write_text(json.dumps(audits, indent=1))
        with open(ROOT / f"transcripts_r{rep}.txt", "a") as f:
            f.write("\n".join(transcripts) + "\n")
    finally:
        R.lock()
    print(json.dumps([[r["run_id"], r["subtype"], r["bucket"], r["failure_kind"], r["n_exp"],
                       r["transcript_clean"]] for r in out] + [{"trap_hits": trap_hits}], indent=0))


def aggregate():
    rows = c0r._read_jsonl(RESULTS)
    rate = c0r._rate
    nb = [r for r in rows if r["bucket"] != "BLOCKED"]

    def by(key, rs):
        return {k: rate([r for r in rs if r[key] == k]) for k in sorted({r[key] for r in rows})}
    per_type = {}
    for st in sorted({r["subtype"] for r in rows}):
        rr = sorted([r for r in rows if r["subtype"] == st], key=lambda r: r["rep"])
        per_type[st] = {"difficulty": rr[0]["difficulty"],
                        "solved": f"{sum(r['bucket'] == 'SOLVED' for r in rr)}/{len(rr)}",
                        "buckets": [r["bucket"] + (f":{r['failure_kind']}" if r["failure_kind"] else "") for r in rr],
                        "n_exp": [r["n_exp"] for r in rr]}
    exps = sum(r["n_exp"] for r in rows)
    ok = sum(r["n_exp_ok"] for r in rows)
    executed = sum(r["n_exp_executed"] for r in rows)
    calls = sum(r["n_cli_calls"] for r in rows)
    cerr = sum(r["n_cli_errors"] for r in rows)
    tok = {}
    for r in rows:
        for k, v in (r["tokens"] or {}).items():
            tok.setdefault(k, []).append(v)
    solved = [r for r in rows if r["bucket"] == "SOLVED"]
    overall = rate(rows)
    rep = {
        "config": CONFIG, "budget": BUDGET,
        "sample": {"runs": len(rows), "types": len(per_type), "instances_per_type": 3,
                   "note": "small sample (n=3 per type, 1 run per instance) -> provisional; pretraining "
                           "contamination possible for generic crackme patterns; dev-set designer = harness author"},
        "buckets": dict(Counter(r["bucket"] for r in rows)),
        "solve_rate_blocked_in_denominator": {"overall": overall, "by_difficulty": by("difficulty", rows),
                                              "by_type": by("subtype", rows)},
        "solve_rate_blocked_excluded": {"overall": rate(nb), "by_difficulty": by("difficulty", nb),
                                        "by_type": by("subtype", nb)},
        "headroom": {"ceiling": overall["rate"] == 1.0, "floor": overall["rate"] == 0.0},
        "per_type": per_type,
        "failure_breakdown": dict(Counter(r["failure_kind"] or "BLOCKED" for r in rows if r["bucket"] != "SOLVED")),
        "failure_kind_source": dict(Counter(r["failure_kind_source"] for r in rows if r["failure_kind_source"])),
        "blocked": {"runs": sum(r["bucket"] == "BLOCKED" for r in rows),
                    "with_block_signal": sum(r["bucket"] == "BLOCKED" and r["block_signal"] for r in rows),
                    "types": dict(Counter(r["subtype"] for r in rows if r["bucket"] == "BLOCKED")),
                    "no_terminal_after_executing": sum(r["bucket"] == "FAILED" and r["session_status"] == "OPEN"
                                                       for r in rows)},
        "tool_lack_mentions_r2_or_decompiler": sum(r["mentions_r2_or_decompiler"] for r in rows),
        "experiments_to_solve": {"distribution": dict(sorted(Counter(r["n_exp"] for r in solved).items())),
                                 "stats": c0r._stats([r["n_exp"] for r in solved]),
                                 "evidence_exp_index": dict(sorted(Counter(r["evidence_exp_index"] for r in solved).items()))},
        "experiments_per_run": c0r._stats([r["n_exp"] for r in rows]),
        "tool_call_validity": {"exp_ok_over_exp": f"{ok}/{exps}", "exp_ok_rate": round(ok / exps, 3) if exps else None,
                               "exp_executed_over_exp": f"{executed}/{exps}",
                               "cli_ok_over_calls": f"{calls - cerr}/{calls}",
                               "cli_ok_rate": round((calls - cerr) / calls, 3) if calls else None},
        "tokens_per_agent": {k: c0r._stats(v) for k, v in tok.items()},
        "tokens_measured_runs": sum(1 for r in rows if r["tokens"]),
        "wall_s_per_run": c0r._stats([r["wall_s"] for r in rows]),
        "wall_s_note": "from the agent's first CLI call to its terminal call (or last call); None if no call",
        "flag_without_solution": sum(r["verdict"] == verifier.FLAG_WITHOUT_SOLUTION for r in rows),
        "non_container_executions": sum(r["non_container_exps"] for r in rows),
        "blindness": {"trap_hits": sorted({h for r in rows for h in r["batch_trap_hits"]}),
                      "transcripts_clean": sum(1 for r in rows if r["transcript_clean"]),
                      "transcripts_missing": sum(1 for r in rows if r["transcript_clean"] is None),
                      "nonconforming": {r["run_id"]: r["transcript_nonconforming"] for r in rows
                                        if r["transcript_clean"] is False}},
        "give_up_self_reported": [{"run_id": r["run_id"], "subtype": r["subtype"], **r["give_up"]}
                                  for r in rows if r["give_up"]],
    }
    (ROOT / "report.json").write_text(json.dumps(rep, indent=2) + "\n")
    (ROOT / "report.md").write_text(_md(rep))
    print(json.dumps(rep, indent=2))


def _md(rep):
    def cell(r):
        return f"{r['solved']}/{r['runs']} ({r['rate']}, {r['wilson95']})"
    a, b = rep["solve_rate_blocked_in_denominator"], rep["solve_rate_blocked_excluded"]
    L = ["# Phase 8 — Reverse C0 baseline (auto-generated by eval/p8_runner.py)", "",
         f"Config: {rep['config']}", f"Budget/run: {rep['budget']}",
         f"Sample: {rep['sample']['runs']} runs — **{rep['sample']['note']}**", "",
         f"Buckets: {rep['buckets']}", "",
         "| group | solved/runs (BLOCKED counted) | solved/runs (BLOCKED excluded) |", "|---|---|---|",
         f"| overall | {cell(a['overall'])} | {cell(b['overall'])} |"]
    for sect, name in (("by_difficulty", "difficulty"), ("by_type", "type")):
        for k in a[sect]:
            L.append(f"| {name}={k} | {cell(a[sect][k])} | {cell(b[sect][k])} |")
    L += ["", f"Headroom: {rep['headroom']}", "", "| type | diff | solved | buckets | exps |", "|---|---|---|---|---|"]
    for st, v in rep["per_type"].items():
        L.append(f"| {st} | {v['difficulty']} | {v['solved']} | {', '.join(v['buckets'])} | {v['n_exp']} |")
    L += ["", "## Other metrics", ""] + [f"- {k}: {json.dumps(rep[k])}" for k in (
        "failure_breakdown", "failure_kind_source", "blocked", "tool_lack_mentions_r2_or_decompiler",
        "experiments_to_solve", "experiments_per_run", "tool_call_validity", "tokens_per_agent",
        "tokens_measured_runs", "wall_s_per_run", "flag_without_solution", "non_container_executions",
        "blindness", "give_up_self_reported")] + [""]
    return "\n".join(L)


def main(argv):
    cmd = argv[:1]
    if cmd == ["prepare"] and len(argv) == 2:
        prepare(int(argv[1]))
    elif cmd == ["verify"] and len(argv) >= 3:
        verify_rep(int(argv[1]), argv[2:])
    elif cmd == ["report"]:
        aggregate()
    elif cmd in (["lock"], ["unlock"]):
        getattr(R, cmd[0])()
    elif cmd == ["lockstate"]:
        print(json.dumps({"locked": R.LOCKFILE.exists()}))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
