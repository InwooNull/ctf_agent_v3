"""Phase 11 plumbing proof: the 3 synthetic pwn problems are SOLVED by the
reference (non-LLM) exploits through the interactive session layer, with an
evidence chain, and the verifier's negative branches (FLAG_WITHOUT_SOLUTION,
UNVERIFIED) both fire. Also checks isolation (container profile + network block,
no writes outside the jail) and that no pwn containers linger.

  python3 eval/p11_pwn_proof.py            # -> store/p11_pwn/proof.{json,md}

pass/fail only; recovered flags are never written to the report.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from eval import pwn_scorer  # noqa: E402
from solver import verifier  # noqa: E402
from solver.pwn_harness import PwnHarness  # noqa: E402

VAULT = PROJECT_ROOT / "vault"
ARENA = PROJECT_ROOT / "arena" / "pwn_instances"
MANIFEST = VAULT / "manifest_pwn.json"
OUT = PROJECT_ROOT / "store" / "p11_pwn"
IMAGE = "ctfagent-pwn:0.1"


def _docker_names():
    p = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True)
    return set(p.stdout.split())


def _dir_fingerprint(d):
    return {f.name: f.stat().st_size for f in sorted(Path(d).iterdir()) if f.is_file()}


def _image_present():
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


def main():
    sys.path.insert(0, str(VAULT))
    import ref_pwn  # noqa: E402  (lives in vault/)

    if not _image_present():
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.pwn first")
    if not MANIFEST.exists():
        raise SystemExit("no manifest; run python3 vault/gen_pwn.py first")

    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    cids = sorted(manifest)
    containers_before = _docker_names()
    chall_fp_before = {c: _dir_fingerprint(ARENA / c) for c in cids}

    results, solved_flag, solved_run = [], None, None
    for cid in cids:
        r = ref_pwn.solve(cid, store_root=OUT / "runs", manifest=manifest)
        v = pwn_scorer.score(r["run_dir"], cid)
        exp = next((e for e in _read_exps(r["run_dir"]) if e["exp_id"] == r["exp_id"]), {})
        results.append({
            "cid": cid, "type": r["type"], "exec_status": r["status"],
            "verdict": v["verdict"], "solved": v.get("solved", False),
            "evidence_exp_id": v.get("evidence_exp_id"),
            "flag_recovered": bool(r["flag"]),
            "sandbox_profile": exp.get("sandbox_profile"),
            "network_guaranteed": exp.get("network_guaranteed"),
        })
        if v["verdict"] == verifier.SOLVED and solved_flag is None:
            solved_flag, solved_run = r["flag"], r

    # --- negative branches, built from the legitimately recovered flag ---
    branch = _branch_checks(solved_flag, solved_run, manifest)

    # --- isolation + zombie checks ---
    containers_after = _docker_names()
    leaked = sorted(n for n in (containers_after - containers_before) if n.startswith("ctfagent_"))
    chall_unchanged = all(_dir_fingerprint(ARENA / c) == chall_fp_before[c] for c in cids)
    all_container = all(x["sandbox_profile"] == "container" for x in results)
    all_netblock = all(x["network_guaranteed"] for x in results)

    checks = {
        "all_three_solved": all(x["verdict"] == "SOLVED" for x in results) and len(results) == 3,
        "evidence_chain_present": all(x["evidence_exp_id"] for x in results),
        "branch_flag_without_solution": branch["fws_verdict"] == "FLAG_WITHOUT_SOLUTION",
        "branch_unverified": branch["unverified_verdict"] == "UNVERIFIED",
        "isolation_container_profile": all_container,
        "isolation_network_blocked": all_netblock,
        "isolation_no_writes_outside_jail": chall_unchanged,
        "no_pwn_containers_leaked": leaked == [],
    }
    report = {
        "image": IMAGE, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "problems": [{k: x[k] for k in ("cid", "type", "exec_status", "verdict",
                                        "solved", "evidence_exp_id", "flag_recovered",
                                        "sandbox_profile", "network_guaranteed")} for x in results],
        "negative_branches": branch,
        "isolation": {"leaked_containers": leaked, "challenge_dirs_unchanged": chall_unchanged,
                      "every_exp_container": all_container, "every_exp_network_blocked": all_netblock},
        "checks": checks,
        "pass": all(checks.values()),
        "note": "pass/fail only; recovered flags are not recorded here (blindness).",
    }
    (OUT / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
    (OUT / "proof.md").write_text(_md(report))
    print(_md(report))
    return 0 if report["pass"] else 1


def _branch_checks(flag, run, manifest):
    """FWS: correct flag, but cited experiment did not print it. UNVERIFIED: wrong flag."""
    out = {"fws_verdict": None, "unverified_verdict": None}
    if not flag or run is None:
        return out
    cid = run["cid"]
    # FLAG_WITHOUT_SOLUTION: benign experiment (no flag in stdout) cited as evidence
    h = PwnHarness(f"branch-fws-{cid}", ARENA / cid, store_root=OUT / "branch")
    o = h.run_experiment({"name": "benign", "code": "print('benign output, no flag here')", "timeout": 30})
    h.report_candidate(flag, [o.exp_id])          # correct flag, but o.stdout has no flag
    out["fws_verdict"] = pwn_scorer.score(h.run_dir, cid)["verdict"]
    # UNVERIFIED: a wrong flag, even with an executed experiment
    h2 = PwnHarness(f"branch-unv-{cid}", ARENA / cid, store_root=OUT / "branch")
    o2 = h2.run_experiment({"name": "benign2", "code": "print('still no flag')", "timeout": 30})
    h2.report_candidate("flag{this_is_not_the_flag}", [o2.exp_id])
    out["unverified_verdict"] = pwn_scorer.score(h2.run_dir, cid)["verdict"]
    return out


def _read_exps(run_dir):
    p = Path(run_dir) / "experiments.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def _md(r):
    lines = [f"# Phase 11 — pwn plumbing proof ({r['image']})", "",
             f"generated {r['generated_at']}", "",
             "| problem | type | exec | verdict | evidence | profile | net-blocked |",
             "|---|---|---|---|---|---|---|"]
    for p in r["problems"]:
        lines.append(f"| {p['cid']} | {p['type']} | {p['exec_status']} | {p['verdict']} | "
                     f"{'yes' if p['evidence_exp_id'] else 'no'} | {p['sandbox_profile']} | "
                     f"{p['network_guaranteed']} |")
    lines += ["", f"- negative branches: FWS={r['negative_branches']['fws_verdict']}, "
                  f"UNVERIFIED={r['negative_branches']['unverified_verdict']}",
              f"- leaked pwn containers: {r['isolation']['leaked_containers'] or 'none'}",
              f"- challenge dirs unchanged: {r['isolation']['challenge_dirs_unchanged']}", "",
              "## checks", ""]
    for k, v in r["checks"].items():
        lines.append(f"- [{'PASS' if v else 'FAIL'}] {k}")
    lines += ["", f"## RESULT: {'PASS' if r['pass'] else 'FAIL'}", ""]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
