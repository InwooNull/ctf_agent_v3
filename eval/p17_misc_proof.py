"""Phase 17 plumbing proof: the 4 synthetic Misc/Forensics problems are SOLVED by
the reference (non-LLM) tool-chain solvers through the MiscHarness, with an
evidence chain, and the verifier's negative branches (FLAG_WITHOUT_SOLUTION,
UNVERIFIED) both fire. Also checks isolation (container profile + network block,
challenge dirs unchanged) and that no misc containers linger.

  python3 eval/p17_misc_proof.py            # -> store/p17_misc/proof.{json,md}

pass/fail only; recovered flags are never written to the report or the log.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from eval import misc_scorer  # noqa: E402
from solver import verifier, misc_scripted_driver  # noqa: E402
from solver.misc_harness import MiscHarness  # noqa: E402

VAULT = PROJECT_ROOT / "vault"
ARENA = PROJECT_ROOT / "arena" / "misc_instances"
MANIFEST = VAULT / "manifest_misc.json"
OUT = PROJECT_ROOT / "store" / "p17_misc"
IMAGE = "ctfagent-misc:0.1"


def _docker_names():
    p = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                       capture_output=True, text=True)
    return set(p.stdout.split())


def _dir_fingerprint(d):
    return {f.name: f.stat().st_size for f in sorted(Path(d).iterdir()) if f.is_file()}


def _image_present():
    return subprocess.run(["docker", "image", "inspect", IMAGE],
                          capture_output=True).returncode == 0


def _read_exps(run_dir):
    p = Path(run_dir) / "experiments.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def main():
    sys.path.insert(0, str(VAULT))
    import ref_misc  # noqa: E402  (lives in vault/)

    if not _image_present():
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.misc first")
    if not MANIFEST.exists():
        raise SystemExit("no manifest; run python3 vault/gen_misc.py first")

    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    cids = sorted(manifest, key=lambda c: (manifest[c]["type"], c))
    containers_before = _docker_names()
    chall_fp_before = {c: _dir_fingerprint(ARENA / c) for c in cids}
    stamp = time.strftime("%Y%m%dT%H%M%S")

    results, solved_flag, solved_run = [], None, None
    for cid in cids:
        typ = manifest[cid]["type"]
        t0 = time.monotonic()
        h, out, flag = misc_scripted_driver.solve(
            ARENA / cid, f"{stamp}-{cid}", ref_misc.code_for(typ),
            f"reference tool-chain solver for {typ}", store_root=OUT / "runs")
        v = misc_scorer.score(h.run_dir, cid)
        exp = next((e for e in _read_exps(h.run_dir) if e["exp_id"] == out.exp_id), {})
        results.append({
            "cid": cid, "type": typ, "exec_status": out.execution_status,
            "verdict": v["verdict"], "solved": v.get("solved", False),
            "evidence_exp_id": v.get("evidence_exp_id"),
            "flag_recovered": bool(flag),
            "sandbox_profile": exp.get("sandbox_profile"),
            "network_guaranteed": exp.get("network_guaranteed"),
            "secs": round(time.monotonic() - t0, 1),
        })
        if v["verdict"] == verifier.SOLVED and solved_flag is None:
            solved_flag, solved_run = flag, h

    branch = _branch_checks(solved_flag, solved_run, manifest)

    containers_after = _docker_names()
    leaked = sorted(n for n in (containers_after - containers_before)
                    if n.startswith("ctfagent"))
    chall_unchanged = all(_dir_fingerprint(ARENA / c) == chall_fp_before[c] for c in cids)
    all_container = all(x["sandbox_profile"] == "container" for x in results)
    all_netblock = all(x["network_guaranteed"] for x in results)
    n_solved = sum(1 for x in results if x["solved"])

    report = {
        "image": IMAGE,
        "n_instances": len(cids),
        "n_solved": n_solved,
        "all_solved": n_solved == len(cids),
        "branch_flag_without_solution": branch["fws_verdict"] == "FLAG_WITHOUT_SOLUTION",
        "branch_unverified": branch["unverified_verdict"] == "UNVERIFIED",
        "isolation_container_profile": all_container,
        "isolation_network_blocked": all_netblock,
        "challenge_dirs_unchanged": chall_unchanged,
        "no_misc_containers_leaked": leaked == [],
        "per_instance": [{k: r[k] for k in (
            "cid", "type", "exec_status", "verdict", "solved", "flag_recovered",
            "sandbox_profile", "network_guaranteed", "secs")} for r in results],
        "negative_branches": branch,
        "isolation": {"leaked_containers": leaked,
                      "challenge_dirs_unchanged": chall_unchanged,
                      "every_exp_container": all_container,
                      "every_exp_network_blocked": all_netblock},
    }
    report["PASS"] = all([
        report["all_solved"], report["branch_flag_without_solution"],
        report["branch_unverified"], report["isolation_container_profile"],
        report["isolation_network_blocked"], report["challenge_dirs_unchanged"],
        report["no_misc_containers_leaked"],
    ])

    (OUT / "proof.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    (OUT / "proof.md").write_text(_md(report))
    print(_md(report))
    return 0 if report["PASS"] else 1


def _branch_checks(flag, run, manifest):
    """FWS: correct flag, but cited experiment did not print it. UNVERIFIED: wrong flag."""
    cid = run.challenge_id
    # FLAG_WITHOUT_SOLUTION: a benign experiment (prints no flag) cited as evidence
    h = MiscHarness(f"branch-fws-{cid}", ARENA / cid, store_root=OUT / "branch")
    o = h.run_experiment({"name": "noop", "code": "print('benign, no flag here')",
                          "timeout": 30, "nondeterministic": True})
    h.report_candidate(flag, [o.exp_id])          # correct flag, cited exp has no flag
    fws = misc_scorer.score(h.run_dir, cid)
    # UNVERIFIED: a wrong flag, even with an executed experiment
    h2 = MiscHarness(f"branch-unv-{cid}", ARENA / cid, store_root=OUT / "branch")
    o2 = h2.run_experiment({"name": "noop", "code": "print('benign')",
                            "timeout": 30, "nondeterministic": True})
    h2.report_candidate("FLAG{00000000000000ff}", [o2.exp_id])
    unv = misc_scorer.score(h2.run_dir, cid)
    return {"fws_verdict": fws["verdict"], "unverified_verdict": unv["verdict"]}


def _md(r):
    lines = [f"# Phase 17 Misc/Forensics plumbing proof — {'PASS' if r['PASS'] else 'FAIL'}",
             "",
             f"- image: `{r['image']}`",
             f"- solved: {r['n_solved']}/{r['n_instances']} (evidence chain)",
             f"- negative branches: FWS={r['negative_branches']['fws_verdict']}, "
             f"UNVERIFIED={r['negative_branches']['unverified_verdict']}",
             f"- isolation: every exp container={r['isolation']['every_exp_container']}, "
             f"network blocked={r['isolation']['every_exp_network_blocked']}",
             f"- challenge dirs unchanged: {r['challenge_dirs_unchanged']}",
             f"- leaked misc containers: {r['isolation']['leaked_containers'] or 'none'}",
             "",
             "| cid | type | exec | verdict | solved | profile | net_off | secs |",
             "|-----|------|------|---------|--------|---------|---------|------|"]
    for x in r["per_instance"]:
        lines.append(f"| {x['cid']} | {x['type']} | {x['exec_status']} | {x['verdict']} | "
                     f"{x['solved']} | {x['sandbox_profile']} | {x['network_guaranteed']} | {x['secs']} |")
    lines.append("")
    lines.append("Flags are never written here; SOLVED means the scorer matched the "
                 "hidden key AND a container experiment printed it.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
