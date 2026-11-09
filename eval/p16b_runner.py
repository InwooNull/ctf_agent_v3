"""Phase 16b runner: budget/self-repair LEVER PROBE. Re-run ONLY the 11 problems that the Phase 16a
clean C0 baseline left FAILED, changing exactly ONE thing vs C0 -- the budget (15->30 experiments,
1800->3600 s wall). Everything else is identical C0 (simple ReAct, no pack/experience/multi-attempt,
inspect-first, pwndbg-FREE on image 0.1). The isolated question: how many FAILED flip to SOLVED when the
only added resource is budget + room to self-repair within the same run? (A conversion of 0 is still a
valid result -- it means the bottleneck is capability, not budget.)

  python3 eval/p16b_runner.py prepare <rep>                       # 11 fresh runs in store/p16b_c0 + trap + lock
  python3 eval/p16b_runner.py verify <rep> <transcript.jsonl>...  # trap + CLI-only audit -> verifier -> rows
  python3 eval/p16b_runner.py report                              # before/after conversion -> store/p16b_c0/report.{json,md}
  python3 eval/p16b_runner.py lock | unlock | lockstate

The 16 already-SOLVED problems are NOT re-run; the 2 outcome-blind exclusions from 16a (brainflop
undeployable, feather API-safeguard) stay excluded.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("p8_runner", PROJECT_ROOT / "eval" / "p8_runner.py")
P8 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P8)
R, c0r = P8.R, P8.c0r

ROOT = PROJECT_ROOT / "store" / "p16b_c0"
BOOT = ROOT / "_boot"
P14_ROOT = PROJECT_ROOT / "store" / "p14_c0"
P16A_ROOT = PROJECT_ROOT / "store" / "p16a_c0"
VAULT = R.VAULT
ARENA = PROJECT_ROOT / "arena" / "real_pwn"
KEYS = VAULT / "scorer_keys_pwn_real"
MANIFEST = VAULT / "manifest_pwn_real.json"
BUDGET = {"max_experiments": 30, "wall_s": 3600, "exp_timeout_s": 60}   # the LEVER: 2x C0

# The 11 problems FAILED by the Phase 16a baseline (9 reused-from-P14 + 2 re-run), by challenge id.
# (Excludes the 2 outcome-blind exclusions brainflop/feather.)
TARGETS = ["rp_06696f", "rp_7f2db1", "rp_84e8fd", "rp_b85cd3", "rp_656314", "rp_1cb31a", "rp_5cc6ae",
           "rp_1d8e9c", "rp_80db35", "rp_318b7c", "rp_7144fe"]

CONFIG = dict(P8.CONFIG, category="pwn", image="ctfagent-pwn:0.1",
              set="NYU CTF Bench pwn A-local holdout — Phase 16a FAILED 11 (budget-lever probe)",
              boundary="pwn-service 2-uid, --network none",
              inspect_first="prompt + e01 not citable", pwndbg=False,
              lever="budget 30 exps / 3600 s (2x C0); self-repair via inspect-first loop")

P8.ROOT, P8.RESULTS = ROOT, ROOT / "results.jsonl"
P8.ARENA, P8.KEYS, P8.CONFIG, P8.BUDGET = ARENA, KEYS, CONFIG, BUDGET
R.ROOT, R.RESULTS, R.LOCKFILE, R.TRAPFILE = ROOT, P8.RESULTS, ROOT / "lock.json", ROOT / "trap.json"
R.CLI_RE = re.compile(r"^cd ~/ctf_agent_v3 && python3 arena/pwn_cli\.py "
                      r"(p16bc0-r(\d+)-rp_[0-9a-f]{6}) (info|exp|report|give_up|status)\b(.*)$")

NEARMISS_RE = re.compile(r"validated|locally|ready|out of (the )?budget|ran out|exhausted|near-miss|"
                         r"already-working|complete chain|primitives proven|last of the|remaining budget",
                         re.I)
RATE_LIMIT_RE = re.compile(r"rate.?limit|429|api error|usage polic|overloaded|safeguard|\[cyber\]", re.I)


def _manifest_reps():
    man = json.loads(MANIFEST.read_text())
    return [{"id": cid, "rep": k, "subtype": man[cid]["name"],
             "difficulty": f"{man[cid]['year']}{'q' if 'Quals' in man[cid]['event'] else 'f'}"}
            for k in (1,) for cid in TARGETS]


P8._manifest_reps = _manifest_reps
P8.run_id_for = lambda m: f"p16bc0-r{m['rep']}-{m['id']}"


def _secrets():
    ROOT.mkdir(parents=True, exist_ok=True)
    cache = ROOT / "lock_paths.json"
    base = ["vault", "eval/scorer_keys", "eval/packs", "eval/make_dev_set.py", "eval/make_dev_challenge.py",
            "store/c0", "store/runs", "store/c0b", "store/c0b2", "store/p6_c0", "store/p6_c1",
            "store/p6_validate.log", "store/p8_c0", "store/p10_c0"]
    try:
        cache.write_text(json.dumps(base)); return base
    except OSError:
        return json.loads(cache.read_text())


def prepare(rep):
    ROOT.mkdir(parents=True, exist_ok=True)
    R.STATIC_SECRETS = P8.STATIC_SECRETS = _secrets()
    R.unlock()
    try:
        made = []
        for m in [m for m in _manifest_reps() if m["rep"] == rep]:
            rid = P8.run_id_for(m)
            d = ROOT / rid
            if d.exists():
                raise SystemExit(f"{d} exists")
            d.mkdir(parents=True)
            sess = {"run_id": rid, "challenge_id": m["id"], "rep": rep,
                    "challenge_dir": str(ARENA / m["id"]), "status": "OPEN", "exp_count": 0,
                    "experiments": [], "started_at": None, **CONFIG}
            (d / "session.json").write_text(json.dumps(sess, indent=2, sort_keys=True))
            flag = json.loads((KEYS / f"{m['id']}.json").read_text())["flag"]
            bf = BOOT / rid
            bf.mkdir(parents=True, exist_ok=True)
            (bf / "flag").write_text(flag)
            (bf / "flag").chmod(0o600)
            made.append(rid)
        n = R.arm_trap()
    finally:
        R.lock()
    print(json.dumps({"rep": rep, "runs": made, "trap_files": n, "locked": R.LOCKFILE.exists()}))


def _before_rows():
    """The Phase-16a FAILED rows for these 11 (9 from p14_c0, 2 from p16a_c0), indexed by challenge id."""
    rows = c0r._read_jsonl(P14_ROOT / "results.jsonl") + c0r._read_jsonl(P16A_ROOT / "results.jsonl")
    out = {}
    for r in rows:
        if r["challenge_id"] in TARGETS and r["bucket"] == "FAILED":
            out[r["challenge_id"]] = r      # p16a rows (CryptoPwn/pgtp) override p14 if both present
    return out


def report():
    R.STATIC_SECRETS = P8.STATIC_SECRETS = _secrets()
    R.unlock()
    try:
        after = c0r._read_jsonl(P8.RESULTS)
        before = _before_rows()
        # outcome-blind re-exclusion (infra interruption, non-terminal) — same rule as 16a
        reexcluded, rows = {}, []
        for r in after:
            final = (r.get("final_text_excerpt") or "")
            terminal = r["session_status"] in ("REPORTED", "GIVE_UP")
            interrupted = r.get("block_signal") or bool(RATE_LIMIT_RE.search(final)) or r["bucket"] == "BLOCKED"
            if (not terminal) and interrupted:
                reexcluded[r["run_id"]] = f"infra interruption, non-terminal ({r['subtype']})"
            else:
                rows.append(r)

        def bnm(cid):   # was the 16a failure a budget-bound near-miss (validated/ready chain)?
            b = before.get(cid, {})
            return bool(NEARMISS_RE.search((b.get("give_up") or {}).get("reason", "") or ""))

        converted = [r for r in rows if r["bucket"] == "SOLVED"]
        still = [r for r in rows if r["bucket"] != "SOLVED"]
        table = []
        for r in sorted(rows, key=lambda x: x["challenge_id"]):
            cid = r["challenge_id"]
            b = before.get(cid, {})
            table.append({
                "cid": cid, "subtype": r["subtype"],
                "before_16a": {"bucket": b.get("bucket"), "failure_kind": b.get("failure_kind"),
                               "n_exp": b.get("n_exp"), "near_miss": bnm(cid)},
                "after_16b": {"bucket": r["bucket"], "failure_kind": r["failure_kind"],
                              "n_exp": r["n_exp"], "n_exp_executed": r["n_exp_executed"],
                              "wall_s": r.get("wall_s")},
                "converted": r["bucket"] == "SOLVED",
            })
        lever = {
            "converted_from_near_miss": sorted(r["challenge_id"] for r in converted if bnm(r["challenge_id"])),
            "converted_from_impl_bug": sorted(r["challenge_id"] for r in converted
                                              if before.get(r["challenge_id"], {}).get("failure_kind")
                                              == "implementation_bug" and not bnm(r["challenge_id"])),
            "converted_from_analysis": sorted(r["challenge_id"] for r in converted
                                              if before.get(r["challenge_id"], {}).get("failure_kind")
                                              == "analysis_failure"),
        }
        rep = {
            "probe": "budget/self-repair lever, isolated (C0 + 30 exps/3600 s; nothing else added)",
            "image": "ctfagent-pwn:0.1 (pwndbg-free)", "budget": BUDGET,
            "targets": "the 11 problems FAILED by the Phase 16a clean baseline",
            "n_targets": len(TARGETS), "n_valid": len(rows), "reexcluded_infra": reexcluded,
            "conversions": {"n": len(converted), "ids": sorted(r["challenge_id"] for r in converted),
                            "of_valid": f"{len(converted)}/{len(rows)}"},
            "lever_breakdown": lever,
            "still_failed": [{"cid": r["challenge_id"], "subtype": r["subtype"],
                              "failure_kind": r["failure_kind"],
                              "reason": (r.get("give_up") or {}).get("reason", "")[:400]}
                             for r in sorted(still, key=lambda x: x["challenge_id"])],
            "before_after": table,
            "integrity": {"flag_without_solution": sum(1 for r in rows if r["verdict"] == "FLAG_WITHOUT_SOLUTION"),
                          "non_container_executions": sum(r.get("non_container_exps", 0) for r in rows),
                          "trap_hits": (after[0].get("batch_trap_hits") if after else None),
                          "transcripts_clean": sum(1 for r in rows if r.get("transcript_clean")),
                          "transcripts_nonclean": sum(1 for r in rows if r.get("transcript_clean") is False)},
            "cost": {"n_exp": {r["challenge_id"]: r["n_exp"] for r in rows},
                     "wall_s": {r["challenge_id"]: r.get("wall_s") for r in rows},
                     "tokens_output": {r["challenge_id"]: (r.get("tokens") or {}).get("output") for r in rows}},
            "implication": ("if conversions come mostly from near-miss/impl rows -> the bottleneck was "
                            "BUDGET/implementation, not knowledge; if ~0 -> the bottleneck is capability "
                            "(hard heap/ObjC), and budget is not the lever."),
            "limits": ("probe, x1, provisional; CSAW contamination constant shared across configs; "
                       "pwndbg-free; only the 11 prior-FAILED re-run (16 SOLVED and 2 exclusions untouched); "
                       "a conversion is not a new baseline number — it isolates the budget lever."),
        }
        (ROOT / "report.json").write_text(json.dumps(rep, indent=2) + "\n")
        (ROOT / "report.md").write_text(_md(rep))
        print(_md(rep))
    finally:
        R.lock()


def _md(rep):
    c = rep["conversions"]
    L = [f"# Phase 16b — budget/self-repair lever probe (auto-generated by eval/p16b_runner.py)\n",
         f"probe: {rep['probe']}",
         f"image: `{rep['image']}`  ·  budget {rep['budget']}  ·  targets: {rep['targets']}\n",
         f"## conversions: {c['of_valid']} prior-FAILED flipped to SOLVED  -> {c['ids']}\n",
         f"- lever breakdown: {json.dumps(rep['lever_breakdown'])}",
         f"- re-excluded (infra, non-terminal): {json.dumps(rep['reexcluded_infra'])}",
         f"- integrity: {json.dumps(rep['integrity'])}\n",
         "## before (16a) -> after (16b)\n",
         "| challenge | 16a | near-miss? | 16b | exps 16a->16b | wall_s |",
         "|---|---|---|---|---|---|"]
    for t in rep["before_after"]:
        b, a = t["before_16a"], t["after_16b"]
        L.append(f"| {t['subtype']} | {b['bucket']}/{b['failure_kind']} | {b['near_miss']} | "
                 f"**{a['bucket']}**{('/'+str(a['failure_kind'])) if a['failure_kind'] else ''} | "
                 f"{b['n_exp']}->{a['n_exp']} | {a['wall_s']} |")
    L.append("\n## still failed (residual cause)\n")
    for s in rep["still_failed"]:
        L.append(f"- **{s['subtype']}** ({s['failure_kind']}): {s['reason'][:240]}")
    L.append(f"\n## implication\n{rep['implication']}\n\n## limits\n{rep['limits']}\n")
    return "\n".join(L)


def main(argv):
    R.STATIC_SECRETS = P8.STATIC_SECRETS = _secrets()
    if argv[:1] == ["prepare"] and len(argv) == 2:
        prepare(int(argv[1])); return 0
    if argv[:1] == ["report"]:
        report(); return 0
    return P8.main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
