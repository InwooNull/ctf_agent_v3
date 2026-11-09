"""Phase 21 plumbing proof: the A-local real web challenges promoted by ctfagent-web:0.2
(single-service PHP) are SOLVED by the reference (non-LLM) exploits through the WebServiceHarness
2-uid boundary, each with an evidence chain, over loopback HTTP only. Also proves the anti-cheat
boundary (the agent uid cannot read the service-owned flag directly), that the verifier's negative
branches (FLAG_WITHOUT_SOLUTION, UNVERIFIED) both fire, that every experiment is a --network none
container, that the public challenge dirs are unchanged, and that no web containers linger.

  python3 eval/p21_web_proof.py            # -> store/p21_web/proof.{json,md}

Measurement is NOT the goal (pass/fail only). Recovered flags are never written to the report or the
log. The challenge source lives in the vault (blind); the agent run gets only a private (black-box)
service tree it cannot read + the loopback HTTP tube.
"""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import verifier, web_scripted_driver  # noqa: E402
from solver.web_harness import WebServiceHarness  # noqa: E402

VAULT = PROJECT_ROOT / "vault"
ARENA = PROJECT_ROOT / "arena" / "real_web"
WRITEUPS = VAULT / "writeups_web_real"
KEYS = VAULT / "scorer_keys_web_real"
CLASSIFICATION = PROJECT_ROOT / "store" / "p21_web" / "classification.json"
OUT = PROJECT_ROOT / "store" / "p21_web"
IMAGE = "ctfagent-web:0.2"

# anti-cheat probe: a direct read of the service-owned source/flag must find nothing (agent uid owns
# none of /srv/tree in private mode, and the flag file is 0640 service-owned).
DIRECT_READ = r'''
import os
hits = []
for p in ["/srv/tree", "/srv/tree/flag.txt", "/srv/tree/guessharder.php", "/srv/data",
          "/srv/tree/poems", "/flag.txt", "/flag"]:
    try:
        if os.path.isdir(p):
            os.listdir(p); hits.append("listdir:" + p)
        else:
            open(p, "rb").read(); hits.append("read:" + p)
    except OSError:
        pass
print("DIRECT_READ_HITS", hits)
'''


def _image_present():
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


def _docker_names():
    p = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True)
    return set(p.stdout.split())


def _dir_fingerprint(d):
    return {str(f.relative_to(d)): f.stat().st_size for f in sorted(Path(d).rglob("*")) if f.is_file()}


def _read_exps(run_dir):
    p = Path(run_dir) / "experiments.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def _flag(cid):
    return json.loads((KEYS / f"{cid}.json").read_text())["flag"]


def _stage_instance(cid, nyu_id, spec):
    """Build a private black-box instance under store/p21_web/_stage/<cid>/ from the withheld source."""
    src_root = WRITEUPS / cid / "files"
    inst = OUT / "_stage" / cid
    if inst.exists():
        shutil.rmtree(inst)
    tree = inst / "tree"
    tree.mkdir(parents=True)
    if "src_subdir" in spec:
        shutil.copytree(src_root / spec["src_subdir"], tree, dirs_exist_ok=True)
    else:
        for f in spec["src_files"]:
            shutil.copyfile(src_root / f, tree / Path(f).name)
    chall = {"id": cid, "category": "web", "app_rel": "app.py",
             "launch": spec["launch"], "source_mode": spec["source_mode"],
             "docroot": spec.get("docroot", ""), "router": spec.get("router", ""),
             "flag_file": spec.get("flag_file", ""), "flag_token": spec.get("flag_token", "")}
    (inst / "challenge.json").write_text(json.dumps(chall, indent=1) + "\n")
    return inst


def _solve_on(instance_dir, store_set, run_id, code, flag, image, timeout=90):
    """Mirror web_scripted_driver.solve but on an explicit image (0.2)."""
    store_set = Path(store_set)
    boot = store_set / "_boot" / run_id
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "flag").write_text(flag)
    h = WebServiceHarness("harness", instance_dir, store_root=store_set / run_id, image=image)
    h.record_hypothesis("reference exploit over loopback HTTP", priority_band="high")
    out = h.run_experiment({"name": "solve", "code": code, "timeout": timeout})
    m = web_scripted_driver.CAND_RE.search(out.stdout or "")
    reported = m.group(1) if m else None
    if reported:
        h.report_candidate(reported, [out.exp_id])
    return h, out, reported


def main():
    import ref_web_real  # from vault/ (added to path below)

    if not _image_present():
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.web2 first")
    if not CLASSIFICATION.exists():
        raise SystemExit("run python3 eval/real_web_reclassify.py first")

    OUT.mkdir(parents=True, exist_ok=True)
    cls = json.loads(CLASSIFICATION.read_text())
    a_cids = sorted((cid for cid, r in cls.items() if r["cls"] == "A"),
                    key=lambda c: cls[c]["nyu_id"])
    containers_before = _docker_names()
    chall_fp_before = {c: _dir_fingerprint(ARENA / c) for c in a_cids}
    stamp = time.strftime("%Y%m%dT%H%M%S")

    results, solved_cid = [], None
    for cid in a_cids:
        nyu_id = cls[cid]["nyu_id"]
        spec = ref_web_real.LAUNCH[nyu_id]
        inst = _stage_instance(cid, nyu_id, spec)
        t0 = time.monotonic()
        h, out, reported = _solve_on(inst, OUT / "runs", f"{stamp}-{cid}",
                                     ref_web_real.code_for(nyu_id), _flag(cid), IMAGE)
        v = verifier.verify(h.run_dir, cid, scorer_keys_dir=KEYS)
        exp = next((e for e in _read_exps(h.run_dir) if e["exp_id"] == out.exp_id), {})
        results.append({
            "cid": cid, "nyu_id": nyu_id, "launch": spec["launch"],
            "exec_status": out.execution_status, "verdict": v["verdict"],
            "solved": v.get("solved", False), "flag_recovered": bool(reported),
            "sandbox_profile": exp.get("sandbox_profile"),
            "profile_variant": exp.get("profile_variant"),
            "network_guaranteed": exp.get("network_guaranteed"),
            "secs": round(time.monotonic() - t0, 1),
        })
        if v["verdict"] == verifier.SOLVED and solved_cid is None:
            solved_cid = cid

    anti = _anticheat_check(a_cids, cls, stamp)
    branch = _branch_checks(solved_cid, cls, stamp)

    containers_after = _docker_names()
    leaked = sorted(n for n in (containers_after - containers_before) if n.startswith("ctfagent"))
    chall_unchanged = all(_dir_fingerprint(ARENA / c) == chall_fp_before[c] for c in a_cids)
    all_container = all(x["sandbox_profile"] == "container" for x in results)
    all_variant = all(x["profile_variant"] == "web-service" for x in results)
    all_netblock = all(x["network_guaranteed"] for x in results)
    n_solved = sum(1 for x in results if x["solved"])

    report = {
        "image": IMAGE,
        "n_A_instances": len(a_cids),
        "n_solved": n_solved,
        "all_solved": n_solved == len(a_cids) and len(a_cids) > 0,
        "anticheat_direct_read_blocked": anti["blocked"],
        "anticheat_detail": anti,
        "branch_flag_without_solution": branch["fws_verdict"] == "FLAG_WITHOUT_SOLUTION",
        "branch_unverified": branch["unverified_verdict"] == "UNVERIFIED",
        "isolation_container_profile": all_container and all_variant,
        "isolation_network_blocked": all_netblock,
        "challenge_dirs_unchanged": chall_unchanged,
        "no_web_containers_leaked": leaked == [],
        "per_instance": [{k: r[k] for k in (
            "cid", "nyu_id", "launch", "exec_status", "verdict", "solved", "flag_recovered",
            "sandbox_profile", "profile_variant", "network_guaranteed", "secs")} for r in results],
        "negative_branches": branch,
        "isolation": {"leaked_containers": leaked, "challenge_dirs_unchanged": chall_unchanged,
                      "every_exp_container": all_container, "every_exp_web_service_variant": all_variant,
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


def _anticheat_check(a_cids, cls, stamp):
    import ref_web_real
    cid = a_cids[0]
    nyu_id = cls[cid]["nyu_id"]
    inst = _stage_instance(cid, nyu_id, ref_web_real.LAUNCH[nyu_id])
    h, out, reported = _solve_on(inst, OUT / "anticheat", f"{stamp}-{cid}-direct",
                                 DIRECT_READ, _flag(cid), IMAGE)
    hits = None
    for line in (out.stdout or "").splitlines():
        if line.startswith("DIRECT_READ_HITS"):
            hits = line[len("DIRECT_READ_HITS"):].strip()
    return {"blocked": hits == "[]", "hits_repr": hits, "exec_status": out.execution_status,
            "no_candidate_reported": reported is None}


def _branch_checks(cid, cls, stamp):
    """FWS: correct flag, cited experiment did not print it. UNVERIFIED: wrong flag."""
    import ref_web_real
    nyu_id = cls[cid]["nyu_id"]
    inst = _stage_instance(cid, nyu_id, ref_web_real.LAUNCH[nyu_id])
    flag = _flag(cid)
    set_dir = OUT / "branch"
    rid = f"{stamp}-{cid}-fws"
    (set_dir / "_boot" / rid).mkdir(parents=True, exist_ok=True)
    (set_dir / "_boot" / rid / "flag").write_text(flag)
    h = WebServiceHarness("harness", inst, store_root=set_dir / rid, image=IMAGE)
    o = h.run_experiment({"name": "noop", "code": "print('benign, no flag here')", "timeout": 40})
    h.report_candidate(flag, [o.exp_id])
    fws = verifier.verify(h.run_dir, cid, scorer_keys_dir=KEYS)
    rid2 = f"{stamp}-{cid}-unv"
    (set_dir / "_boot" / rid2).mkdir(parents=True, exist_ok=True)
    (set_dir / "_boot" / rid2 / "flag").write_text(flag)
    h2 = WebServiceHarness("harness", inst, store_root=set_dir / rid2, image=IMAGE)
    o2 = h2.run_experiment({"name": "noop", "code": "print('benign')", "timeout": 40})
    h2.report_candidate("flag{00000000000000ff}", [o2.exp_id])
    unv = verifier.verify(h2.run_dir, cid, scorer_keys_dir=KEYS)
    return {"fws_verdict": fws["verdict"], "unverified_verdict": unv["verdict"]}


def _md(r):
    lines = [f"# Phase 21 Web:0.2 plumbing proof — {'PASS' if r['PASS'] else 'FAIL'}",
             "",
             f"- image: `{r['image']}`",
             f"- A-local real web solved: {r['n_solved']}/{r['n_A_instances']} "
             f"(evidence chain, loopback HTTP only, single-service PHP via `php -S`)",
             f"- anti-cheat (direct flag/source read blocked by 2-uid private tree): "
             f"{r['anticheat_direct_read_blocked']} (hits={r['anticheat_detail']['hits_repr']})",
             f"- negative branches: FWS={r['negative_branches']['fws_verdict']}, "
             f"UNVERIFIED={r['negative_branches']['unverified_verdict']}",
             f"- isolation: every exp container+web-service={r['isolation_container_profile']}, "
             f"network blocked={r['isolation']['every_exp_network_blocked']}",
             f"- challenge dirs unchanged: {r['challenge_dirs_unchanged']}",
             f"- leaked web containers: {r['isolation']['leaked_containers'] or 'none'}",
             "",
             "| cid | nyu_id | launch | exec | verdict | solved | variant | net_off | secs |",
             "|-----|--------|--------|------|---------|--------|---------|---------|------|"]
    for x in r["per_instance"]:
        lines.append(f"| {x['cid']} | {x['nyu_id']} | {x['launch']} | {x['exec_status']} | "
                     f"{x['verdict']} | {x['solved']} | {x['profile_variant']} | "
                     f"{x['network_guaranteed']} | {x['secs']} |")
    lines.append("")
    lines.append("Flags are never written here; SOLVED means the scorer matched the hidden key AND a "
                 "container experiment printed it, reached only through the app's own bug over HTTP.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.path.insert(0, str(VAULT))
    sys.exit(main())
