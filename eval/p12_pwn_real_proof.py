"""Phase 12 proof: K real NYU/CSAW A-local pwn problems are SOLVED by reference exploits through the
session layer in the existing isolation (ctfagent-pwn, --network none), with an evidence chain; the
verifier's FLAG_WITHOUT_SOLUTION / UNVERIFIED branches fire; isolation and zombie-freedom hold; and the
solve path does not touch the vault (blind audit).

  python3 eval/p12_pwn_real_proof.py          # -> store/p12_pwn/proof.{json,md}

Only A-local problems with a reference recipe are proven (solvability of the rest is attested by the
bench's own writeups; this proves the loader/isolation/scoring/session plumbing on real binaries).
pass/fail only; recovered flags are not written to the report.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from eval import pwn_real_scorer  # noqa: E402
from solver import verifier  # noqa: E402
from solver.pwn_harness import PwnHarness  # noqa: E402

VAULT = PROJECT_ROOT / "vault"
ARENA = PROJECT_ROOT / "arena" / "real_pwn"
MANIFEST = VAULT / "manifest_pwn_real.json"
KEYS = VAULT / "scorer_keys_pwn_real"
WRITEUPS = VAULT / "writeups_pwn_real"
OUT = PROJECT_ROOT / "store" / "p12_pwn"
IMAGE = "ctfagent-pwn:0.1"
PROVE_NAMES = {"get_it?", "bigboy", "Password-Checker"}   # the A-local sample with reference recipes


def _docker_names():
    p = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True)
    return set(p.stdout.split())


def _fp(d):
    return {f.name: f.stat().st_size for f in sorted(Path(d).iterdir()) if f.is_file()}


def _atimes(root):
    return {str(p): p.stat().st_atime for p in Path(root).rglob("*") if p.is_file()}


def _image_present():
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


def main():
    sys.path.insert(0, str(VAULT))
    import ref_pwn_real  # noqa: E402

    if not _image_present():
        raise SystemExit(f"{IMAGE} not present")
    if not MANIFEST.exists():
        raise SystemExit("pwn not loaded; run eval/real_pwn_loader.py first")

    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    targets = [cid for cid, m in manifest.items() if m["name"] in PROVE_NAMES]
    cids_all = sorted(manifest)

    containers_before = _docker_names()
    chall_fp_before = {c: _fp(ARENA / c) for c in targets}
    writeups_atime_before = _atimes(WRITEUPS)

    results, solved = [], None
    for cid in sorted(targets):
        flag = json.loads((KEYS / f"{cid}.json").read_text())["flag"]     # scorer-side: place server flag.txt
        r = ref_pwn_real.solve(cid, flag, store_root=OUT / "runs", manifest=manifest)
        v = pwn_real_scorer.score(r["run_dir"], cid)
        exp = next((e for e in _exps(r["run_dir"]) if e["exp_id"] == r["exp_id"]), {})
        results.append({"cid": cid, "name": r["name"], "exec_status": r["status"], "verdict": v["verdict"],
                        "evidence_exp_id": v.get("evidence_exp_id"), "flag_printed": bool(r["flag_printed"]),
                        "sandbox_profile": exp.get("sandbox_profile"),
                        "network_guaranteed": exp.get("network_guaranteed")})
        if v["verdict"] == verifier.SOLVED and solved is None:
            solved = (cid, r["flag_printed"])

    branch = _branches(solved, manifest)

    containers_after = _docker_names()
    writeups_atime_after = _atimes(WRITEUPS)
    leaked = sorted(n for n in (containers_after - containers_before) if n.startswith("ctfagent_"))
    chall_unchanged = all(_fp(ARENA / c) == chall_fp_before[c] for c in targets)
    writeups_untouched = writeups_atime_before == writeups_atime_after

    checks = {
        "k_solved": sum(x["verdict"] == "SOLVED" for x in results) == len(targets) and len(targets) >= 3,
        "evidence_chain_present": all(x["evidence_exp_id"] for x in results),
        "branch_flag_without_solution": branch["fws"] == "FLAG_WITHOUT_SOLUTION",
        "branch_unverified": branch["unverified"] == "UNVERIFIED",
        "isolation_container_profile": all(x["sandbox_profile"] == "container" for x in results),
        "isolation_network_blocked": all(x["network_guaranteed"] for x in results),
        "isolation_no_writes_outside_jail": chall_unchanged,
        "blind_vault_writeups_untouched": writeups_untouched,
        "no_pwn_containers_leaked": leaked == [],
    }
    report = {
        "image": IMAGE, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "aslr": "ON (host/WSL ignores personality under no-new-privileges); chosen problems non-PIE, no libc leak",
        "proven": [{k: x[k] for k in ("cid", "name", "exec_status", "verdict", "evidence_exp_id",
                                      "flag_printed", "sandbox_profile", "network_guaranteed")} for x in results],
        "negative_branches": branch,
        "isolation": {"leaked_containers": leaked, "challenge_dirs_unchanged": chall_unchanged,
                      "vault_writeups_atime_untouched": writeups_untouched},
        "checks": checks, "pass": all(checks.values()),
        "note": "pass/fail only; flags not recorded. A-local solvability of the rest is attested by the "
                "bench writeups; this proves the real-pwn loader/isolation/scoring/session plumbing.",
    }
    (OUT / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
    (OUT / "proof.md").write_text(_md(report))
    print(_md(report))
    return 0 if report["pass"] else 1


def _branches(solved, manifest):
    out = {"fws": None, "unverified": None}
    if not solved:
        return out
    cid, flag = solved
    h = PwnHarness(f"branch-fws-{cid}", ARENA / cid, store_root=OUT / "branch")
    o = h.run_experiment({"name": "benign", "code": "print('benign, no flag')", "timeout": 30})
    h.report_candidate(flag, [o.exp_id])                       # right flag, evidence has none -> FWS
    out["fws"] = pwn_real_scorer.score(h.run_dir, cid)["verdict"]
    h2 = PwnHarness(f"branch-unv-{cid}", ARENA / cid, store_root=OUT / "branch")
    o2 = h2.run_experiment({"name": "benign2", "code": "print('still none')", "timeout": 30})
    h2.report_candidate("flag{wrong_flag_value}", [o2.exp_id])
    out["unverified"] = pwn_real_scorer.score(h2.run_dir, cid)["verdict"]
    return out


def _exps(run_dir):
    p = Path(run_dir) / "experiments.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def _md(r):
    L = [f"# Phase 12 — real pwn (NYU CTF Bench) A-local proof ({r['image']})", "",
         f"generated {r['generated_at']}", f"ASLR: {r['aslr']}", "",
         "| cid | name | exec | verdict | evidence | profile | net-blocked |",
         "|---|---|---|---|---|---|---|"]
    for p in r["proven"]:
        L.append(f"| {p['cid']} | {p['name']} | {p['exec_status']} | {p['verdict']} | "
                 f"{'yes' if p['evidence_exp_id'] else 'no'} | {p['sandbox_profile']} | {p['network_guaranteed']} |")
    L += ["", f"- branches: FWS={r['negative_branches']['fws']}, UNVERIFIED={r['negative_branches']['unverified']}",
          f"- leaked containers: {r['isolation']['leaked_containers'] or 'none'}",
          f"- challenge dirs unchanged: {r['isolation']['challenge_dirs_unchanged']}",
          f"- vault writeups atime untouched by solves: {r['isolation']['vault_writeups_atime_untouched']}",
          "", "## checks", ""]
    for k, v in r["checks"].items():
        L.append(f"- [{'PASS' if v else 'FAIL'}] {k}")
    L += ["", f"## RESULT: {'PASS' if r['pass'] else 'FAIL'}", ""]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
