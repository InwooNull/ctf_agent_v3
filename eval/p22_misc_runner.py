"""Phase 22 runner: Misc/Forensics C0 x1 reconnaissance baseline on the A-local
HOLDOUT subset of the real NYU forensics/misc set (dev excluded, to preserve a
later C1 comparison).

  python3 eval/p22_misc_runner.py prepare 1                       # create all holdout sessions + trap + lock
  python3 eval/p22_misc_runner.py verify 1 <transcript.jsonl>...  # trap + CLI-only audit -> verifier -> rows
  python3 eval/p22_misc_runner.py report                          # -> store/p22_misc/report.{json,md}
  python3 eval/p22_misc_runner.py lock | unlock | lockstate

C0 = simple ReAct, no pack/experience/multi-attempt, inspect-first, budget
12 exps / 1200 s / 90 s-per-exp, image ctfagent-misc:0.1 (plain container,
--network none). Targets come from the PUBLIC Phase-18 classification
(store/p18_misc/classification.json): bucket A, split holdout. Reuses the
Phase-8 machinery (build_row / classify / verify_rep) and the Phase-5b lock /
atime-trap / CLI-only transcript audit, re-pointed at arena/real_misc and
vault/scorer_keys_misc_real. x1 single pass: solve@1 + Wilson only; a trivial
plaintext-exposure anchor split and a forensics-vs-misc split are reported so
the headroom number is readable with the anchors removed.
"""
import importlib.util
import json
import re
import sys
from collections import Counter
from math import sqrt
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("p8_runner", PROJECT_ROOT / "eval" / "p8_runner.py")
P8 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P8)
R, c0r, verifier = P8.R, P8.c0r, P8.verifier

ROOT = PROJECT_ROOT / "store" / "p22_misc"
ARENA = PROJECT_ROOT / "arena" / "real_misc"
VAULT = R.VAULT
KEYS = VAULT / "scorer_keys_misc_real"
MANIFEST = VAULT / "manifest_misc_real.json"
CLASSIFICATION = PROJECT_ROOT / "store" / "p18_misc" / "classification.json"
BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}

CONFIG = {"config": "C0", "category": "misc_forensics", "loop": "single ReAct", "prompt_pack": False,
          "experience_store": False, "attempts_per_run": 1, "inspect_first": "prompt + e01 not citable",
          "image": "ctfagent-misc:0.1", "boundary": "plain container, --network none"}

# Secrets chmod-000 while agents run. vault covers every misc-real key/writeup/manifest/split (the
# actual answers for this phase); the other store dirs hold prior recovered flags / candidate logs.
# store/p18_misc is deliberately NOT locked: it holds classification.json (cid->nyu_id+type+exposure,
# no flags) which this module imports at load time; the vault lock protects the real flags/writeups
# and the CLI-only transcript audit is the detection layer against any stray read.
STATIC_SECRETS = ["vault", "eval/scorer_keys", "eval/packs", "eval/make_dev_set.py",
                  "eval/make_dev_challenge.py", "store/c0", "store/runs", "store/c0b", "store/c0b2",
                  "store/p6_c0", "store/p6_c1", "store/p6_validate.log", "store/p8_c0", "store/p10_c0",
                  "store/p14_c0", "store/p16a_c0"]


def _targets():
    """A-local HOLDOUT rows from the public Phase-18 classification, as manifest entries."""
    rows = json.loads(CLASSIFICATION.read_text())["rows"]
    out = []
    for r in rows:
        if r["bucket"] != "A" or r["split"] != "holdout":
            continue
        out.append({"id": r["cid"], "rep": 1, "subtype": r["category"],         # subtype = forensics|misc
                    "difficulty": r["nyu_id"].split("-")[0],                      # e.g. 2021q / 2023f
                    "nyu_id": r["nyu_id"], "exposure": r["plaintext_exposure"]})
    return sorted(out, key=lambda m: (m["subtype"], m["nyu_id"]))


EXPOSURE = {m["id"]: m["exposure"] for m in _targets()}
NYU = {m["id"]: m["nyu_id"] for m in _targets()}

# Re-point the shared Phase-8 / Phase-5b machinery at this phase's dirs + CLI.
P8.ROOT, P8.RESULTS, P8.ARENA, P8.KEYS = ROOT, ROOT / "results.jsonl", ARENA, KEYS
P8.CONFIG, P8.BUDGET = CONFIG, BUDGET
P8._manifest_reps = _targets
P8.run_id_for = lambda m: f"p22c0-r{m['rep']}-{m['id']}"
R.ROOT, R.RESULTS, R.LOCKFILE, R.TRAPFILE = ROOT, ROOT / "results.jsonl", ROOT / "lock.json", ROOT / "trap.json"
R.STATIC_SECRETS = P8.STATIC_SECRETS = STATIC_SECRETS
R.CLI_RE = re.compile(r"^cd ~/ctf_agent_v3 && python3 arena/misc_cli\.py "
                      r"(p22c0-r(\d+)-mr_[0-9a-f]{6}) (info|exp|report|give_up|status)\b(.*)$")


# ---- auditor + batch verify -------------------------------------------------
# The shared Phase-5b auditor only accepts a `<<EOF` heredoc; the C0 agents fed
# experiment code through the standard `<<'PY'` form. Generalise the CLI-only
# check to any quoted/bare heredoc delimiter (still proves the ONLY thing run is
# the misc_cli command, with code on stdin). Also verify ONLY the runs whose
# transcript is supplied, so the set can be measured in token-bounded batches.
import shlex  # noqa: E402

_HEREDOC = re.compile(r"<<-?\s*'?\"?([A-Za-z_][A-Za-z0-9_]*)'?\"?\s*$")


def _tail_ok(tail):
    """(ok, delim): reject shell operators / command substitution outside quotes;
    allow one trailing heredoc opener `<<DELIM` (any delimiter)."""
    if "$(" in tail or "`" in tail:
        return False, None
    delim = None
    m = _HEREDOC.search(tail)
    if m:
        delim = m.group(1)
        tail = tail[:m.start()]
    lx = shlex.shlex(tail, posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try:
        toks = list(lx)
    except ValueError:
        return False, None
    if any(t in R.SHELL_OPS or t == "<<" for t in toks):
        return False, None
    return True, delim


def _audit(path, rep):
    calls, bad, rids, seen = 0, [], set(), set()
    tok = {"input_uncached": 0, "cache_creation": 0, "cache_read": 0, "output": 0}
    tok_in = tok_out = 0
    for line in open(path, encoding="utf-8"):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("message") or {}
        u = msg.get("usage")
        if rec.get("type") == "assistant" and u and msg.get("id") not in seen:
            seen.add(msg.get("id"))
            tok_in += u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) \
                + u.get("cache_read_input_tokens", 0)
            tok_out += u.get("output_tokens", 0)
            tok["input_uncached"] += u.get("input_tokens", 0)
            tok["cache_creation"] += u.get("cache_creation_input_tokens", 0)
            tok["cache_read"] += u.get("cache_read_input_tokens", 0)
            tok["output"] += u.get("output_tokens", 0)
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            if b.get("type") != "tool_use" or b.get("name") == "SubagentHandback":
                continue
            calls += 1
            cmd = (b.get("input") or {}).get("command", "")
            first = cmd.splitlines()[0] if cmd else json.dumps(b.get("input"))[:200]
            m = R.CLI_RE.match(first) if b.get("name") == "Bash" else None
            ok, delim = _tail_ok(m.group(4)) if m else (False, None)
            multiline_ok = ("\n" not in cmd) or (bool(delim) and cmd.rstrip().endswith("\n" + delim))
            if m and int(m.group(2)) == rep and ok and multiline_ok:
                rids.add(m.group(1))
            else:
                bad.append({"tool": b.get("name"), "first_line": first[:200]})
    return {"transcript": str(path), "tool_calls": calls, "run_ids": sorted(rids), "nonconforming": bad,
            "clean": not bad and len(rids) == 1, "tokens_in": tok_in, "tokens_out": tok_out,
            "tokens_total": tok_in + tok_out, "tokens_breakdown": tok}


R.audit_transcript = _audit


def verify_batch(rep, transcripts):
    """Verify ONLY the runs whose transcript is supplied (token-bounded batches)."""
    R.unlock()
    try:
        trap_hits = R.check_trap()
        audits = [_audit(t, rep) for t in transcripts]
        by_run = {rid: (a, t) for a, t in zip(audits, transcripts) for rid in a["run_ids"]}
        done = {r["run_id"] for r in c0r._read_jsonl(P8.RESULTS)}
        targets = {P8.run_id_for(m): m for m in _targets() if m["rep"] == rep}
        out = []
        for rid in sorted(by_run):
            if rid in done or rid not in targets:
                continue
            a, tpath = by_run[rid]
            out.append(P8.build_row(targets[rid], rid, ROOT / rid, a, tpath, trap_hits))
        with open(P8.RESULTS, "a", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        with open(ROOT / f"audit_r{rep}.json", "a") as f:
            f.write(json.dumps(audits, indent=1) + "\n")
        with open(ROOT / f"transcripts_r{rep}.txt", "a") as f:
            f.write("\n".join(transcripts) + "\n")
        R.arm_trap()        # re-arm AFTER the verifier's own key reads, so the next batch's
        #                     check_trap reflects solver access only, not the runner's reads
    finally:
        R.lock()
    print(json.dumps([[r["challenge_id"], r["subtype"], r["bucket"], r["failure_kind"], r["n_exp"],
                       r["transcript_clean"]] for r in out] + [{"trap_hits": trap_hits}], indent=0))


def _wilson(k, n):
    if not n:
        return [None, None]
    z, p, d = 1.96, k / n, 1 + 1.96**2 / n
    c = p + 1.96**2 / (2 * n)
    h = 1.96 * sqrt(p * (1 - p) / n + 1.96**2 / (4 * n * n))
    return [round((c - h) / d, 3), round((c + h) / d, 3)]


def _cell(rows):
    n = len(rows)
    k = sum(r["bucket"] == "SOLVED" for r in rows)
    return {"solved": k, "runs": n, "rate": round(k / n, 3) if n else None, "wilson95": _wilson(k, n)}


def report():
    R.unlock()
    try:
        rows = c0r._read_jsonl(P8.RESULTS)
        for r in rows:
            r["exposure"] = EXPOSURE.get(r["challenge_id"], "unknown")
            r["nyu_id"] = NYU.get(r["challenge_id"])
        targets = _targets()
        done_ids = {r["challenge_id"] for r in rows}
        pending = sorted(m["id"] for m in targets if m["id"] not in done_ids)

        # outcome-blind infra split: a run that never reached a terminal call AND shows a block/infra
        # signal (API error / rate-limit / safety safeguard / zero experiments) is set apart, not
        # counted as a capability failure. A genuine give_up (terminal) stays in.
        BLOCK_RE = re.compile(r"rate.?limit|429|api error|usage polic|overloaded|content filter|"
                              r"safety|refus|violat", re.I)
        aborted, clean = {}, []
        for r in rows:
            terminal = r["session_status"] in ("REPORTED", "GIVE_UP")
            infra = r.get("block_signal") or bool(BLOCK_RE.search(r.get("final_text_excerpt") or "")) \
                or r["bucket"] == "BLOCKED"
            if (not terminal) and infra:
                aborted[r["run_id"]] = f"non-terminal infra interruption ({r['subtype']}/{r['nyu_id']})"
            else:
                clean.append(r)

        anchors = [r for r in clean if r["exposure"] in ("file", "description")]
        nonanchor = [r for r in clean if r["exposure"] == "none"]
        forensics = [r for r in clean if r["subtype"] == "forensics"]
        misc = [r for r in clean if r["subtype"] == "misc"]

        fk = Counter(r["failure_kind"] or "BLOCKED" for r in clean if r["bucket"] != "SOLVED")
        solved = [r for r in clean if r["bucket"] == "SOLVED"]
        exps = sum(r["n_exp"] for r in clean)
        ok = sum(r["n_exp_ok"] for r in clean)
        executed = sum(r["n_exp_executed"] for r in clean)
        tok = {}
        for r in clean:
            for k, v in (r["tokens"] or {}).items():
                tok.setdefault(k, []).append(v)

        rep = {
            "config": CONFIG, "budget": BUDGET,
            "scope": "Misc/Forensics C0 x1 reconnaissance on the A-local HOLDOUT subset of real NYU "
                     "(dev excluded for a later C1). x1 = no per-problem confidence/variance.",
            "target_holdout_A_local": len(targets),
            "completed": len(rows), "pending": pending, "n_pending": len(pending),
            "aborted_infra_outcome_blind": aborted,
            "n_clean": len(clean),
            "solve_at_1_overall": _cell(clean),
            "solve_at_1_excluding_anchors": _cell(nonanchor),
            "trivial_anchors_plaintext_exposed": {
                **_cell(anchors),
                "ids": sorted((r["nyu_id"], r["exposure"], r["bucket"]) for r in anchors),
                "note": "flag present verbatim in a provided file or the prompt; counted apart so the "
                        "headroom number is not inflated by freebies"},
            "by_category": {"forensics": _cell(forensics), "misc": _cell(misc)},
            "buckets": dict(Counter(r["bucket"] for r in clean)),
            "failure_breakdown": dict(fk),
            "failure_breakdown_legend": {"analysis_failure": "분석실패", "implementation_bug": "구현버그",
                                         "tool_lack": "도구부족", "BLOCKED": "실험 0회"},
            "headroom": {"ceiling": _cell(clean)["rate"] == 1.0, "floor": _cell(clean)["rate"] == 0.0,
                         "ceiling_excl_anchors": _cell(nonanchor)["rate"] == 1.0,
                         "floor_excl_anchors": _cell(nonanchor)["rate"] == 0.0},
            "experiments_to_solve": c0r._stats([r["n_exp"] for r in solved]),
            "experiments_per_run": c0r._stats([r["n_exp"] for r in clean]),
            "tool_call_validity": {"exp_ok_over_exp": f"{ok}/{exps}",
                                   "exp_ok_rate": round(ok / exps, 3) if exps else None,
                                   "exp_executed_over_exp": f"{executed}/{exps}"},
            "flag_without_solution": sum(r["verdict"] == verifier.FLAG_WITHOUT_SOLUTION for r in clean),
            "non_container_executions": sum(r.get("non_container_exps", 0) for r in clean),
            "blindness": {"trap_hits": sorted({h for r in rows for h in (r.get("batch_trap_hits") or [])}),
                          "transcripts_clean": sum(1 for r in clean if r.get("transcript_clean")),
                          "transcripts_nonclean": sum(1 for r in clean if r.get("transcript_clean") is False),
                          "transcripts_missing": sum(1 for r in clean if r.get("transcript_clean") is None)},
            "cost": {"wall_s": c0r._stats([r["wall_s"] for r in clean]),
                     "tokens_per_agent": {k: c0r._stats(v) for k, v in tok.items()},
                     "tokens_measured_runs": sum(1 for r in clean if r.get("tokens"))},
            "solved_ids": sorted((r["nyu_id"], r["exposure"]) for r in solved),
            "give_up_self_reported": [{"nyu_id": r["nyu_id"], "subtype": r["subtype"], **(r["give_up"])}
                                      for r in clean if r.get("give_up")],
            "limits": ("x1 single pass (no variance, no per-problem confidence); real NYU CSAW "
                       "2013-2023 with public writeups -> likely-contaminated constant shared across "
                       "configs, so this is headroom/ranking not absolute skill; holdout-only (dev "
                       "excluded); partial runs reported as completed/{target}."),
        }
        (ROOT / "report.json").write_text(json.dumps(rep, indent=2) + "\n")
        (ROOT / "report.md").write_text(_md(rep))
        print(json.dumps(rep, indent=2))
    finally:
        R.lock()


def _md(rep):
    def line(name, c):
        return f"| {name} | {c['solved']}/{c['runs']} | {c['rate']} | {c['wilson95']} |"
    L = [f"# Phase 22 — Misc/Forensics C0 x1 reconnaissance (auto-generated by eval/p22_misc_runner.py)\n",
         f"config: {rep['config']['config']} · image `{rep['config']['image']}` · "
         f"budget {rep['budget']} · {rep['config']['boundary']}\n",
         f"scope: {rep['scope']}\n",
         f"**completed {rep['completed']}/{rep['target_holdout_A_local']} A-local holdout** "
         f"(clean {rep['n_clean']}, pending {rep['n_pending']}, "
         f"outcome-blind infra-excluded {len(rep['aborted_infra_outcome_blind'])})\n",
         "| group | solved/runs | rate | Wilson95 |", "|---|---|---|---|",
         line("overall (all clean)", rep["solve_at_1_overall"]),
         line("excl. plaintext anchors", rep["solve_at_1_excluding_anchors"]),
         line("plaintext anchors only", rep["trivial_anchors_plaintext_exposed"]),
         line("forensics", rep["by_category"]["forensics"]),
         line("misc", rep["by_category"]["misc"]),
         f"\n- buckets: {json.dumps(rep['buckets'])}",
         f"- failure breakdown (분석실패/구현버그/도구부족/BLOCKED): {json.dumps(rep['failure_breakdown'])}",
         f"- headroom: {json.dumps(rep['headroom'])}",
         f"- anchors: {json.dumps(rep['trivial_anchors_plaintext_exposed']['ids'])}",
         f"- solved ids: {json.dumps(rep['solved_ids'])}",
         f"- pending ({rep['n_pending']}): {json.dumps(rep['pending'])}",
         f"- infra-excluded (outcome-blind): {json.dumps(rep['aborted_infra_outcome_blind'])}",
         f"\n## integrity / cost\n",
         f"- FLAG_WITHOUT_SOLUTION: {rep['flag_without_solution']} · non-container execs: "
         f"{rep['non_container_executions']}",
         f"- blindness: {json.dumps(rep['blindness'])}",
         f"- tool-call validity: {json.dumps(rep['tool_call_validity'])}",
         f"- experiments/run: {json.dumps(rep['experiments_per_run'])} · to-solve: "
         f"{json.dumps(rep['experiments_to_solve'])}",
         f"- cost: {json.dumps(rep['cost'])}",
         f"- give_up self-reported: {json.dumps(rep['give_up_self_reported'])}",
         f"\n## limits\n{rep['limits']}\n"]
    return "\n".join(L)


def main(argv):
    R.STATIC_SECRETS = P8.STATIC_SECRETS = STATIC_SECRETS
    if argv[:1] == ["report"]:
        report()
        return 0
    if argv[:1] == ["verify"] and len(argv) >= 3:
        verify_batch(int(argv[1]), argv[2:])
        return 0
    return P8.main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
