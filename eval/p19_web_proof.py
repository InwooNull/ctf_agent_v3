"""Phase 19 plumbing proof: the 3 synthetic Web problems are SOLVED by the
reference (non-LLM) exploits through the WebServiceHarness 2-uid boundary, each
with an evidence chain, over loopback HTTP only. Also proves the anti-cheat
boundary (the agent uid cannot read the service-owned flag directly), that the
verifier's negative branches (FLAG_WITHOUT_SOLUTION, UNVERIFIED) both fire, that
every experiment is a --network none container, that the public challenge dirs
are unchanged, and that no web containers linger.

  python3 eval/p19_web_proof.py            # -> store/p19_web/proof.{json,md}

pass/fail only; recovered flags are never written to the report or the log.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from eval import web_scorer  # noqa: E402
from solver import verifier, web_scripted_driver  # noqa: E402
from solver.web_harness import WebServiceHarness  # noqa: E402

VAULT = PROJECT_ROOT / "vault"
ARENA = PROJECT_ROOT / "arena" / "web_instances"
MANIFEST = VAULT / "manifest_web.json"
KEYS = VAULT / "scorer_keys_web"
OUT = PROJECT_ROOT / "store" / "p19_web"
IMAGE = "ctfagent-web:0.1"

# anti-cheat probe: try to read the service-owned secret directly (no HTTP bug).
# Under the 2-uid boundary the agent uid owns none of this, so every read must fail.
DIRECT_READ = r'''
import os
hits = []
for p in ["/srv/data", "/srv/data/flag.txt", "/srv/data/app.db", "/srv/data/shop.db",
          "/flag.txt", "/flag"]:
    try:
        if os.path.isdir(p):
            os.listdir(p); hits.append("listdir:" + p)
        else:
            open(p, "rb").read(); hits.append("read:" + p)
    except OSError:
        pass
print("DIRECT_READ_HITS", hits)
'''


def _docker_names():
    p = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                       capture_output=True, text=True)
    return set(p.stdout.split())


def _dir_fingerprint(d):
    return {str(f.relative_to(d)): f.stat().st_size
            for f in sorted(Path(d).rglob("*")) if f.is_file()}


def _image_present():
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


def _read_exps(run_dir):
    p = Path(run_dir) / "experiments.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def _flag(cid):
    return json.loads((KEYS / f"{cid}.json").read_text())["flag"]


def main():
    sys.path.insert(0, str(VAULT))
    import ref_web  # noqa: E402  (lives in vault/)

    if not _image_present():
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.web first")
    if not MANIFEST.exists():
        raise SystemExit("no manifest; run python3 vault/gen_web.py first")

    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    cids = sorted(manifest, key=lambda c: (manifest[c]["type"], c))
    containers_before = _docker_names()
    chall_fp_before = {c: _dir_fingerprint(ARENA / c) for c in cids}
    stamp = time.strftime("%Y%m%dT%H%M%S")

    results, solved_cid = [], None
    for cid in cids:
        typ = manifest[cid]["type"]
        t0 = time.monotonic()
        h, out, reported = web_scripted_driver.solve(
            ARENA / cid, OUT / "runs", f"{stamp}-{cid}", ref_web.code_for(typ),
            f"reference {typ} exploit over loopback HTTP", _flag(cid))
        v = web_scorer.score(h.run_dir, cid)
        exp = next((e for e in _read_exps(h.run_dir) if e["exp_id"] == out.exp_id), {})
        results.append({
            "cid": cid, "type": typ, "exec_status": out.execution_status,
            "verdict": v["verdict"], "solved": v.get("solved", False),
            "evidence_exp_id": v.get("evidence_exp_id"),
            "flag_recovered": bool(reported),
            "sandbox_profile": exp.get("sandbox_profile"),
            "profile_variant": exp.get("profile_variant"),
            "network_guaranteed": exp.get("network_guaranteed"),
            "secs": round(time.monotonic() - t0, 1),
        })
        if v["verdict"] == verifier.SOLVED and solved_cid is None:
            solved_cid = cid

    anti = _anticheat_check(cids, manifest, stamp)
    branch = _branch_checks(solved_cid, stamp)

    containers_after = _docker_names()
    leaked = sorted(n for n in (containers_after - containers_before) if n.startswith("ctfagent"))
    chall_unchanged = all(_dir_fingerprint(ARENA / c) == chall_fp_before[c] for c in cids)
    all_container = all(x["sandbox_profile"] == "container" for x in results)
    all_variant = all(x["profile_variant"] == "web-service" for x in results)
    all_netblock = all(x["network_guaranteed"] for x in results)
    n_solved = sum(1 for x in results if x["solved"])

    report = {
        "image": IMAGE,
        "n_instances": len(cids),
        "n_solved": n_solved,
        "all_solved": n_solved == len(cids),
        "anticheat_direct_read_blocked": anti["blocked"],
        "anticheat_detail": anti,
        "branch_flag_without_solution": branch["fws_verdict"] == "FLAG_WITHOUT_SOLUTION",
        "branch_unverified": branch["unverified_verdict"] == "UNVERIFIED",
        "isolation_container_profile": all_container and all_variant,
        "isolation_network_blocked": all_netblock,
        "challenge_dirs_unchanged": chall_unchanged,
        "no_web_containers_leaked": leaked == [],
        "per_instance": [{k: r[k] for k in (
            "cid", "type", "exec_status", "verdict", "solved", "flag_recovered",
            "sandbox_profile", "profile_variant", "network_guaranteed", "secs")} for r in results],
        "negative_branches": branch,
        "isolation": {"leaked_containers": leaked,
                      "challenge_dirs_unchanged": chall_unchanged,
                      "every_exp_container": all_container,
                      "every_exp_web_service_variant": all_variant,
                      "every_exp_network_blocked": all_netblock},
    }
    report["PASS"] = all([
        report["all_solved"], report["anticheat_direct_read_blocked"],
        report["branch_flag_without_solution"], report["branch_unverified"],
        report["isolation_container_profile"], report["isolation_network_blocked"],
        report["challenge_dirs_unchanged"], report["no_web_containers_leaked"],
    ])

    (OUT / "proof.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    (OUT / "proof.md").write_text(_md(report))
    print(_md(report))
    return 0 if report["PASS"] else 1


def _anticheat_check(cids, manifest, stamp):
    """Across the boundary, a direct read of the service-owned secret must find nothing."""
    cid = cids[0]
    h, out, reported = web_scripted_driver.solve(
        ARENA / cid, OUT / "anticheat", f"{stamp}-{cid}-direct", DIRECT_READ,
        "attempt direct read of the flag (should be blocked)", _flag(cid))
    text = out.stdout or ""
    hits = None
    for line in text.splitlines():
        if line.startswith("DIRECT_READ_HITS"):
            hits = line[len("DIRECT_READ_HITS"):].strip()
    return {"blocked": hits == "[]", "hits_repr": hits, "exec_status": out.execution_status,
            "no_candidate_reported": reported is None}


def _branch_checks(cid, stamp):
    """FWS: correct flag, but cited experiment did not print it. UNVERIFIED: wrong flag.
    Reuses the real boot-flag staging so the harness path is identical to a real solve."""
    flag = _flag(cid)
    set_dir = OUT / "branch"
    # FLAG_WITHOUT_SOLUTION: a benign experiment (prints no flag) cited as evidence
    rid = f"{stamp}-{cid}-fws"
    (set_dir / "_boot" / rid).mkdir(parents=True, exist_ok=True)
    (set_dir / "_boot" / rid / "flag").write_text(flag)
    h = WebServiceHarness("harness", ARENA / cid, store_root=set_dir / rid)
    o = h.run_experiment({"name": "noop", "code": "print('benign, no flag here')", "timeout": 40})
    h.report_candidate(flag, [o.exp_id])              # correct flag, cited exp has no flag
    fws = web_scorer.score(h.run_dir, cid)
    # UNVERIFIED: a wrong flag, even with an executed experiment
    rid2 = f"{stamp}-{cid}-unv"
    (set_dir / "_boot" / rid2).mkdir(parents=True, exist_ok=True)
    (set_dir / "_boot" / rid2 / "flag").write_text(flag)
    h2 = WebServiceHarness("harness", ARENA / cid, store_root=set_dir / rid2)
    o2 = h2.run_experiment({"name": "noop", "code": "print('benign')", "timeout": 40})
    h2.report_candidate("FLAG{00000000000000ff}", [o2.exp_id])
    unv = web_scorer.score(h2.run_dir, cid)
    return {"fws_verdict": fws["verdict"], "unverified_verdict": unv["verdict"]}


def _md(r):
    lines = [f"# Phase 19 Web plumbing proof — {'PASS' if r['PASS'] else 'FAIL'}",
             "",
             f"- image: `{r['image']}`",
             f"- solved: {r['n_solved']}/{r['n_instances']} (evidence chain, loopback HTTP only)",
             f"- anti-cheat (direct flag read blocked by 2-uid boundary): "
             f"{r['anticheat_direct_read_blocked']} (hits={r['anticheat_detail']['hits_repr']})",
             f"- negative branches: FWS={r['negative_branches']['fws_verdict']}, "
             f"UNVERIFIED={r['negative_branches']['unverified_verdict']}",
             f"- isolation: every exp container+web-service={r['isolation_container_profile']}, "
             f"network blocked={r['isolation']['every_exp_network_blocked']}",
             f"- challenge dirs unchanged: {r['challenge_dirs_unchanged']}",
             f"- leaked web containers: {r['isolation']['leaked_containers'] or 'none'}",
             "",
             "| cid | type | exec | verdict | solved | variant | net_off | secs |",
             "|-----|------|------|---------|--------|---------|---------|------|"]
    for x in r["per_instance"]:
        lines.append(f"| {x['cid']} | {x['type']} | {x['exec_status']} | {x['verdict']} | "
                     f"{x['solved']} | {x['profile_variant']} | {x['network_guaranteed']} | {x['secs']} |")
    lines.append("")
    lines.append("Flags are never written here; SOLVED means the scorer matched the hidden key "
                 "AND a container experiment printed it, reached only through the app's bug.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
