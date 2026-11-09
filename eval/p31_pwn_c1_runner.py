"""Phase 31 runner: Pwn C1 (cheatsheet) vs C0, paired x1 on ONE hard-heap holdout.

Measures whether the pwn knowledge pack (skills/pwn/*, the C1 lever) converts the
Phase-16a heap-capability failure CryptoPwn (rp_318b7c). C0 and C1 are byte-identical
in budget (15 exp / 1800 s), image (ctfagent-pwn:0.1, pwndbg-free), tools, boundary and
blindness — the ONLY difference is that the C1 sub-agent's prompt carries the cheatsheet
(injected by the orchestrator at spawn via orchestrator.skill_pack.inject). Same problem,
same blind 2-uid pwn-service boundary, --network none; the flag is reachable only by
exploiting the live service.

  python3 eval/p31_pwn_c1_runner.py prepare <c0|c1>
  python3 eval/p31_pwn_c1_runner.py verify  <c0|c1> <transcript.jsonl>...
  python3 eval/p31_pwn_c1_runner.py report
  python3 eval/p31_pwn_c1_runner.py lock|unlock|lockstate <c0|c1>

Reuses eval/p8_runner.py (classification/verifier/build_row) and eval/c0b_runner.py
(lock / atime trap / CLI-only audit) exactly like eval/p23_pwn_runner.py. No performance
claim: reports a single paired conversion result + the residual cause.
"""
import importlib.util
import json
import re
import shlex
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("p8_runner", PROJECT_ROOT / "eval" / "p8_runner.py")
P8 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P8)
R, c0r, verifier = P8.R, P8.c0r, P8.verifier

P31_ROOT = PROJECT_ROOT / "store" / "p31_pwn"
ARENA = PROJECT_ROOT / "arena" / "real_pwn"
VAULT = R.VAULT
KEYS = VAULT / "scorer_keys_pwn_real"
MANIFEST = VAULT / "manifest_pwn_real.json"
BASELINE = PROJECT_ROOT / "store" / "p16a_c0"
P14_ROOT = PROJECT_ROOT / "store" / "p14_c0"

TARGET = "rp_318b7c"            # CryptoPwn — glibc-2.31 heap, 16a FAILED (no leak / heap work)
TARGETS = [TARGET]

CONFIGS = {
    "c0": {"prefix": "p31c0", "dir": "c0", "image": "ctfagent-pwn:0.1", "pwndbg": False,
           "reps": (1,), "budget": {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60},
           "lever": "C0 (no cheatsheet)"},
    "c1": {"prefix": "p31c1", "dir": "c1", "image": "ctfagent-pwn:0.1", "pwndbg": False,
           "reps": (1,), "budget": {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60},
           "lever": "C1 (pwn skill pack injected)"},
}
BASE_SECRETS = ["vault", "store/c0", "store/runs", "eval/scorer_keys", "eval/packs",
                "eval/make_dev_set.py", "eval/make_dev_challenge.py",
                "store/p14_c0", "store/p16a_c0", "store/p22_misc", "store/p23_pwn"]


def _manifest_reps_for(cfg):
    man = json.loads(MANIFEST.read_text())
    return [{"id": cid, "rep": k, "subtype": man[cid]["name"],
             "difficulty": f"{man[cid]['year']}{'q' if 'Quals' in man[cid]['event'] else 'f'}"}
            for k in cfg["reps"] for cid in TARGETS]


def _select(config):
    if config not in CONFIGS:
        raise SystemExit(f"unknown config {config!r}; pick c0 or c1")
    cfg = CONFIGS[config]
    root = P31_ROOT / cfg["dir"]
    root.mkdir(parents=True, exist_ok=True)
    pfx = cfg["prefix"]
    conf = dict(P8.CONFIG, config=f"P31:{config}", category="pwn", image=cfg["image"],
                set="NYU CTF Bench pwn holdout — 16a heap-FAILED CryptoPwn (1)",
                boundary="pwn-service 2-uid, --network none",
                inspect_first="prompt + e01 not citable", pwndbg=cfg["pwndbg"],
                lever=cfg["lever"], attempts_per_run=1)
    P8.ROOT, P8.RESULTS = root, root / "results.jsonl"
    P8.ARENA, P8.KEYS, P8.MANIFEST = ARENA, KEYS, MANIFEST
    P8.CONFIG, P8.BUDGET = conf, cfg["budget"]
    P8._manifest_reps = lambda: _manifest_reps_for(cfg)
    P8.run_id_for = lambda m: f"{pfx}-r{m['rep']}-{m['id']}"
    sibling = [f"store/p31_pwn/{CONFIGS[c]['dir']}" for c in CONFIGS if c != config]
    R.STATIC_SECRETS = P8.STATIC_SECRETS = BASE_SECRETS + sibling
    R.ROOT, R.RESULTS = root, root / "results.jsonl"
    R.LOCKFILE, R.TRAPFILE = root / "lock.json", root / "trap.json"
    R.CLI_RE = re.compile(r"^cd ~/ctf_agent_v3 && python3 arena/pwn_cli\.py "
                          rf"({pfx}-r(\d+)-rp_[0-9a-f]{{6}}) (info|exp|report|give_up|status)\b(.*)$")
    return cfg, root


def prepare(config):
    cfg, root = _select(config)
    R.unlock()
    try:
        made = []
        for m in _manifest_reps_for(cfg):
            cid, rid = m["id"], P8.run_id_for(m)
            d = root / rid
            if d.exists():
                raise SystemExit(f"{d} exists")
            d.mkdir(parents=True)
            (d / "session.json").write_text(json.dumps(
                {"run_id": rid, "challenge_id": cid, "rep": m["rep"],
                 "challenge_dir": str(ARENA / cid), "status": "OPEN", "exp_count": 0,
                 "experiments": [], "started_at": None, **P8.CONFIG}, indent=2, sort_keys=True))
            bf = root / "_boot" / rid
            bf.mkdir(parents=True, exist_ok=True)
            (bf / "flag").write_text(json.loads((KEYS / f"{cid}.json").read_text())["flag"])
            (bf / "flag").chmod(0o600)
            made.append(rid)
        n = R.arm_trap()
    finally:
        R.lock()
    print(json.dumps({"config": config, "runs": made, "trap_files": n,
                      "locked": R.LOCKFILE.exists()}))


# ---- CLI-only transcript audit (mirrors p23) --------------------------------
_HEREDOC = re.compile(r"<<-?\s*'?\"?([A-Za-z_][A-Za-z0-9_]*)'?\"?\s*$")


def _tail_ok(tail):
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
    return {"transcript": str(path), "tool_calls": calls, "run_ids": sorted(rids),
            "nonconforming": bad, "clean": not bad and len(rids) == 1,
            "tokens_in": tok_in, "tokens_out": tok_out, "tokens_total": tok_in + tok_out,
            "tokens_breakdown": {"output": tok_out}}


def verify(config, transcripts):
    cfg, root = _select(config)
    R.audit_transcript = _audit
    R.unlock()
    try:
        trap_hits = R.check_trap()
        audits = [_audit(t, 1) for t in transcripts]
        by_run = {rid: (a, t) for a, t in zip(audits, transcripts) for rid in a["run_ids"]}
        done = {r["run_id"] for r in c0r._read_jsonl(P8.RESULTS)}
        targets = {P8.run_id_for(m): m for m in _manifest_reps_for(cfg)}
        out = []
        for rid in sorted(by_run):
            if rid in done or rid not in targets:
                continue
            a, tpath = by_run[rid]
            out.append(P8.build_row(targets[rid], rid, root / rid, a, tpath, trap_hits))
        with open(P8.RESULTS, "a", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        (root / "audit_r1.json").write_text(json.dumps(audits, indent=1))
        R.arm_trap()
    finally:
        R.lock()
    print(json.dumps([[r["challenge_id"], r["bucket"], r["failure_kind"], r["n_exp"],
                       r["transcript_clean"]] for r in out] + [{"trap_hits": trap_hits}]))


def _rows(config):
    _select(config)
    return c0r._read_jsonl(P31_ROOT / CONFIGS[config]["dir"] / "results.jsonl")


def report():
    base = {}
    for r in c0r._read_jsonl(BASELINE / "results.jsonl") + c0r._read_jsonl(P14_ROOT / "results.jsonl"):
        if r["challenge_id"] == TARGET and TARGET not in base:
            base[TARGET] = r
    per = {}
    for config in CONFIGS:
        rr = [r for r in _rows(config) if r["challenge_id"] == TARGET]
        solved = any(r["bucket"] == "SOLVED" for r in rr)
        per[config] = {
            "lever": CONFIGS[config]["lever"], "budget": CONFIGS[config]["budget"],
            "completed": bool(rr), "bucket": (rr[0]["bucket"] if rr else None),
            "solved": solved, "n_exp": (rr[0]["n_exp"] if rr else None),
            "wall_s": (rr[0].get("wall_s") if rr else None),
            "failure_kind": (rr[0].get("failure_kind") if rr else None),
            "give_up": (rr[0].get("give_up") if rr else None),
            "tokens_output": ((rr[0].get("tokens") or {}).get("output") if rr else None),
            "fws": sum(r["verdict"] == verifier.FLAG_WITHOUT_SOLUTION for r in rr),
            "non_container_execs": sum(r.get("non_container_exps", 0) for r in rr),
            "transcript_clean": (rr[0].get("transcript_clean") if rr else None),
            "batch_trap_hits": sorted({h for r in rr for h in (r.get("batch_trap_hits") or [])}),
        }
    c0s, c1s = per["c0"]["solved"], per["c1"]["solved"]
    verdict = ("C1_CONVERTED" if (c1s and not c0s) else
               "BOTH_SOLVED" if (c0s and c1s) else
               "NO_CONVERSION" if (not c0s and not c1s) else "C1_REGRESSED")
    rep = {
        "probe": "Phase 31 — Pwn C1 (cheatsheet) vs C0 on CryptoPwn (rp_318b7c), paired x1",
        "target": TARGET, "target_name": "CryptoPwn (glibc-2.31 heap, 16a FAILED)",
        "baseline_16a": {"bucket": base.get(TARGET, {}).get("bucket"),
                         "give_up": base.get(TARGET, {}).get("give_up")},
        "per_config": per, "verdict": verdict,
        "integrity": {"fws_total": sum(p["fws"] for p in per.values()),
                      "non_container_total": sum(p["non_container_execs"] for p in per.values()),
                      "trap_hits_any": sorted({h for p in per.values() for h in p["batch_trap_hits"]}),
                      "transcripts_nonclean": [c for c in CONFIGS if per[c]["transcript_clean"] is False]},
    }
    P31_ROOT.mkdir(parents=True, exist_ok=True)
    (P31_ROOT / "report.json").write_text(json.dumps(rep, indent=1))
    print(json.dumps(rep, indent=1))
    return rep


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    cmd = argv[0]
    if cmd == "prepare":
        prepare(argv[1])
    elif cmd == "verify":
        verify(argv[1], argv[2:])
    elif cmd == "report":
        report()
    elif cmd in ("lock", "unlock") and len(argv) == 2:
        _select(argv[1]); getattr(R, cmd)(); print(json.dumps({"locked": R.LOCKFILE.exists()}))
    elif cmd == "lockstate" and len(argv) == 2:
        _select(argv[1]); print(json.dumps({"locked": R.LOCKFILE.exists()}))
    else:
        raise SystemExit(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
