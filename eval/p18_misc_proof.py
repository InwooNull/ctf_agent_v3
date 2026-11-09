"""Phase 18 sample proof: a SAMPLE (K=4) of the real NYU forensics/misc A-set is
SOLVED by reference tool-chain solvers through the MiscHarness, with an evidence
chain, proving the loader / isolation / scoring plumbing runs on REAL files. Also
checks the verifier's negative branches (FLAG_WITHOUT_SOLUTION, UNVERIFIED),
isolation (container profile + network block, solver only ever mounts arena/,
challenge dirs unchanged), no lingering containers, and a blind atime audit
(the writeups/solutions are never touched by the solve).

  python3 eval/p18_misc_proof.py            # -> store/p18_misc/proof.{json,md}

NOT a capability measurement. pass/fail only; recovered flags are never written.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from solver import verifier, misc_scripted_driver  # noqa: E402
from solver.misc_harness import MiscHarness  # noqa: E402

V = PROJECT / "vault"
ARENA = PROJECT / "arena" / "real_misc"
MANIFEST = V / "manifest_misc_real.json"
WRITEUPS = V / "writeups_misc_real"
OUT = PROJECT / "store" / "p18_misc"
REAL_KEYS = V / "scorer_keys_misc_real"
IMAGE = "ctfagent-misc:0.1"


def _docker_names():
    p = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True)
    return set(p.stdout.split())


def _dir_fp(d):
    return {f.name: f.stat().st_size for f in sorted(Path(d).iterdir()) if f.is_file()}


def _image_present():
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


def _read_exps(run_dir):
    p = Path(run_dir) / "experiments.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def _input_dir_of(run_dir, exp_id):
    p = Path(run_dir) / "commands.jsonl"
    if not p.exists():
        return None
    for line in p.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("experiment_id") == exp_id:
            # input files are the script + mounted challenge files; report their common root
            ins = [Path(x) for x in rec.get("input_files", []) if "/arena/" in x or "/vault/" in x]
            return str(ins[0].parent) if ins else None
    return None


def main():
    sys.path.insert(0, str(V))
    import ref_misc_real  # noqa: E402

    if not _image_present():
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.misc first")
    if not MANIFEST.exists():
        raise SystemExit("no manifest; run eval/real_misc_loader.py first")

    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    by_nyu = {rec["nyu_id"]: cid for cid, rec in manifest.items()}
    sample = [(nyu, by_nyu[nyu]) for nyu in ref_misc_real.SAMPLE_NYU if nyu in by_nyu]
    stamp = time.strftime("%Y%m%dT%H%M%S")

    containers_before = _docker_names()
    chall_fp_before = {cid: _dir_fp(ARENA / cid) for _, cid in sample}
    # blind atime audit: snapshot the writeup (solution) dir atimes
    wu_atime_before = {cid: (WRITEUPS / cid).stat().st_atime_ns
                       for _, cid in sample if (WRITEUPS / cid).exists()}

    results, solved_flag, solved_run = [], None, None
    for nyu, cid in sample:
        t0 = time.monotonic()
        h, out, flag = misc_scripted_driver.solve(
            ARENA / cid, f"{stamp}-{cid}", ref_misc_real.code_for_nyu(nyu),
            f"reference capture solver for {nyu}", store_root=OUT / "runs")
        v = verifier.verify(h.run_dir, cid, scorer_keys_dir=REAL_KEYS)
        exp = next((e for e in _read_exps(h.run_dir) if e["exp_id"] == out.exp_id), {})
        idir = _input_dir_of(h.run_dir, out.exp_id)
        results.append({
            "cid": cid, "nyu_id": nyu, "category": manifest[cid]["category"],
            "split": manifest[cid]["split"], "exec_status": out.execution_status,
            "verdict": v["verdict"], "solved": v.get("solved", False),
            "evidence_exp_id": v.get("evidence_exp_id"), "flag_recovered": bool(flag),
            "sandbox_profile": exp.get("sandbox_profile"),
            "network_guaranteed": exp.get("network_guaranteed"),
            "input_under_arena": bool(idir and "/arena/" in idir and "/vault/" not in idir),
            "secs": round(time.monotonic() - t0, 1),
        })
        if v["verdict"] == verifier.SOLVED and solved_flag is None:
            solved_flag, solved_run = flag, h

    branch = _branch_checks(solved_flag, solved_run)

    containers_after = _docker_names()
    leaked = sorted(n for n in (containers_after - containers_before) if n.startswith("ctfagent"))
    chall_unchanged = all(_dir_fp(ARENA / cid) == chall_fp_before[cid] for _, cid in sample)
    wu_untouched = all((WRITEUPS / cid).stat().st_atime_ns == wu_atime_before[cid]
                       for _, cid in sample if cid in wu_atime_before)
    all_container = all(x["sandbox_profile"] == "container" for x in results)
    all_netblock = all(x["network_guaranteed"] for x in results)
    all_arena = all(x["input_under_arena"] for x in results)
    n_solved = sum(1 for x in results if x["solved"])

    report = {
        "image": IMAGE, "sample_size": len(sample), "n_solved": n_solved,
        "all_solved": n_solved == len(sample),
        "branch_flag_without_solution": branch["fws_verdict"] == "FLAG_WITHOUT_SOLUTION",
        "branch_unverified": branch["unverified_verdict"] == "UNVERIFIED",
        "isolation_container_profile": all_container,
        "isolation_network_blocked": all_netblock,
        "solver_input_only_arena": all_arena,
        "challenge_dirs_unchanged": chall_unchanged,
        "writeups_atime_untouched": wu_untouched,
        "no_misc_containers_leaked": leaked == [],
        "per_instance": [{k: r[k] for k in (
            "cid", "nyu_id", "category", "split", "exec_status", "verdict", "solved",
            "flag_recovered", "sandbox_profile", "network_guaranteed",
            "input_under_arena", "secs")} for r in results],
        "negative_branches": branch,
        "isolation": {"leaked_containers": leaked, "challenge_dirs_unchanged": chall_unchanged,
                      "every_exp_container": all_container, "every_exp_network_blocked": all_netblock,
                      "solver_input_only_arena": all_arena, "writeups_atime_untouched": wu_untouched},
    }
    report["PASS"] = all([
        report["all_solved"], report["branch_flag_without_solution"], report["branch_unverified"],
        report["isolation_container_profile"], report["isolation_network_blocked"],
        report["solver_input_only_arena"], report["challenge_dirs_unchanged"],
        report["no_misc_containers_leaked"],
    ])

    (OUT / "proof.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    (OUT / "proof.md").write_text(_md(report))
    print(_md(report))
    return 0 if report["PASS"] else 1


def _branch_checks(flag, run):
    cid = run.challenge_id
    h = MiscHarness(f"branch-fws-{cid}", ARENA / cid, store_root=OUT / "branch")
    o = h.run_experiment({"name": "noop", "code": "print('benign, no flag here')",
                          "timeout": 30, "nondeterministic": True})
    h.report_candidate(flag, [o.exp_id])          # correct flag, cited exp has no flag
    fws = verifier.verify(h.run_dir, cid, scorer_keys_dir=REAL_KEYS)
    h2 = MiscHarness(f"branch-unv-{cid}", ARENA / cid, store_root=OUT / "branch")
    o2 = h2.run_experiment({"name": "noop", "code": "print('benign')",
                            "timeout": 30, "nondeterministic": True})
    h2.report_candidate("flag{this_is_not_the_real_flag}", [o2.exp_id])
    unv = verifier.verify(h2.run_dir, cid, scorer_keys_dir=REAL_KEYS)
    return {"fws_verdict": fws["verdict"], "unverified_verdict": unv["verdict"]}


def _md(r):
    L = [f"# Phase 18 real-misc sample proof — {'PASS' if r['PASS'] else 'FAIL'}", "",
         f"- image: `{r['image']}`  sample: {r['n_solved']}/{r['sample_size']} SOLVED (evidence chain)",
         f"- negative branches: FWS={r['negative_branches']['fws_verdict']}, "
         f"UNVERIFIED={r['negative_branches']['unverified_verdict']}",
         f"- isolation: every exp container={r['isolation']['every_exp_container']}, "
         f"net blocked={r['isolation']['every_exp_network_blocked']}, "
         f"solver input only arena={r['isolation']['solver_input_only_arena']}",
         f"- blind audit: writeups atime untouched={r['isolation']['writeups_atime_untouched']}, "
         f"challenge dirs unchanged={r['challenge_dirs_unchanged']}",
         f"- leaked misc containers: {r['isolation']['leaked_containers'] or 'none'}", "",
         "| cid | nyu_id | cat | split | exec | verdict | solved | profile | net_off | arena_only | secs |",
         "|-----|--------|-----|-------|------|---------|--------|---------|---------|------------|------|"]
    for x in r["per_instance"]:
        L.append(f"| {x['cid']} | {x['nyu_id']} | {x['category']} | {x['split']} | {x['exec_status']} | "
                 f"{x['verdict']} | {x['solved']} | {x['sandbox_profile']} | {x['network_guaranteed']} | "
                 f"{x['input_under_arena']} | {x['secs']} |")
    L += ["", "Sample only (K=4), NOT a capability measurement — the goal is proving the loader, "
          "isolation and scoring plumbing run on real NYU files. Flags are never written here."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
