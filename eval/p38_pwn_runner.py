"""Phase 38 runner: Pwn C0 vs C1+tools, paired x1, on the heap_hard holdout subset.

Measures whether the pwn knowledge pack + specialist tools (the C1+tools lever) convert
the Phase-16a/23/31 heap-capability failures. C0 and C1 are identical in budget
(15 exp / 1800 s), boundary (pwn-service 2-uid, --network none), blindness and problem
set; the ONLY differences are:
  - C0 : image ctfagent-pwn:0.1, pwndbg-free, NO cheatsheet injected.
  - C1 : image ctfagent-pwn:0.3 (pwndbg + angr + ropper), cheatsheet injected at spawn
         by orchestrator.skill_pack.inject(..., "pwn").

Subset (heap_hard, deployable, not libc-mismatched):
  rp_318b7c CryptoPwn, rp_b85cd3 unsafe-linking, rp_84e8fd horrorscope,
  rp_7f2db1 Salt Server, rp_7144fe pop_goes_the_printer (ObjC-decompile gap, noted).

pwndbg is the tool under test here (heap_hard is its domain). angr is in the image/router
as capability insurance but this subset is NOT angr-shaped; its sanity check is the
separate eval/p38_pwn_trace.py. No performance claim: reports a paired conversion table +
which tool (if any) each C1 solve actually used.

  python3 eval/p38_pwn_runner.py prepare <c0|c1>
  python3 eval/p38_pwn_runner.py verify  <c0|c1> <transcript.jsonl>...
  python3 eval/p38_pwn_runner.py report
  python3 eval/p38_pwn_runner.py lock|unlock|lockstate <c0|c1>

Reuses eval/p8_runner.py + eval/c0b_runner.py machinery exactly like p23/p31.
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

P38_ROOT = PROJECT_ROOT / "store" / "p38_pwn"
ARENA = PROJECT_ROOT / "arena" / "real_pwn"
VAULT = R.VAULT
KEYS = VAULT / "scorer_keys_pwn_real"
MANIFEST = VAULT / "manifest_pwn_real.json"
BASELINE = PROJECT_ROOT / "store" / "p16a_c0"
P14_ROOT = PROJECT_ROOT / "store" / "p14_c0"

# heap_hard subset — see module docstring. Names are for the report only.
TARGETS = ["rp_318b7c", "rp_b85cd3", "rp_84e8fd", "rp_7f2db1", "rp_7144fe"]
NAMES = {"rp_318b7c": "CryptoPwn (glibc-2.31 heap)",
         "rp_b85cd3": "unsafe-linking (safe-linking heap)",
         "rp_84e8fd": "horrorscope (glibc-2.34 UAF)",
         "rp_7f2db1": "Salt Server (forking own-port)",
         "rp_7144fe": "pop_goes_the_printer (GNUstep/ObjC — essential gap = ObjC decompile)"}

CONFIGS = {
    "c0": {"prefix": "p38c0", "dir": "c0", "image": "ctfagent-pwn:0.1", "pwndbg": False,
           "reps": (1,), "budget": {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60},
           "lever": "C0 (no cheatsheet, no specialist tools, image 0.1)"},
    "c1": {"prefix": "p38c1", "dir": "c1", "image": "ctfagent-pwn:0.3", "pwndbg": True,
           "reps": (1,), "budget": {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60},
           "lever": "C1+tools (cheatsheet + pwndbg/angr/ropper, image 0.3)"},
}
BASE_SECRETS = ["vault", "store/c0", "store/runs", "eval/scorer_keys", "eval/packs",
                "eval/make_dev_set.py", "eval/make_dev_challenge.py",
                "store/p14_c0", "store/p16a_c0", "store/p22_misc", "store/p23_pwn",
                "store/p31_pwn", "store/p34_rehearsal", "store/p36_pwn_b1",
                "store/p36_rev", "store/p36_misc", "store/p36_web"]

TOOL_TOKENS = {"pwndbg": "pwndbg", "gdbinit": "pwndbg", "angr": "angr", "claripy": "angr",
               "ropper": "ropper", "one_gadget": "one_gadget", "ROPgadget": "ROPgadget"}


def _manifest_reps_for(cfg):
    man = json.loads(MANIFEST.read_text())
    return [{"id": cid, "rep": k, "subtype": man[cid]["name"],
             "difficulty": f"{man[cid]['year']}{'q' if 'Quals' in man[cid]['event'] else 'f'}"}
            for k in cfg["reps"] for cid in TARGETS]


def _select(config):
    if config not in CONFIGS:
        raise SystemExit(f"unknown config {config!r}; pick c0 or c1")
    cfg = CONFIGS[config]
    root = P38_ROOT / cfg["dir"]
    root.mkdir(parents=True, exist_ok=True)
    pfx = cfg["prefix"]
    conf = dict(P8.CONFIG, config=f"P38:{config}", category="pwn", image=cfg["image"],
                set="NYU pwn holdout — heap_hard subset (5): CryptoPwn/unsafe-linking/"
                    "horrorscope/Salt Server/pop_goes",
                boundary="pwn-service 2-uid, --network none",
                inspect_first="prompt + e01 not citable", pwndbg=cfg["pwndbg"],
                lever=cfg["lever"], attempts_per_run=1)
    P8.ROOT, P8.RESULTS = root, root / "results.jsonl"
    P8.ARENA, P8.KEYS, P8.MANIFEST = ARENA, KEYS, MANIFEST
    P8.CONFIG, P8.BUDGET = conf, cfg["budget"]
    P8._manifest_reps = lambda: _manifest_reps_for(cfg)
    P8.run_id_for = lambda m: f"{pfx}-r{m['rep']}-{m['id']}"
    sibling = [f"store/p38_pwn/{CONFIGS[c]['dir']}" for c in CONFIGS if c != config]
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


# ---- CLI-only transcript audit (mirrors p23/p31) + tool-usage detection -----
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
    tool_hits = set()
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
            # tool-usage detection: any specialist tool token appearing in a command body
            low = cmd.lower()
            for tok, tool in TOOL_TOKENS.items():
                if tok.lower() in low:
                    tool_hits.add(tool)
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
            "tokens_breakdown": {"output": tok_out}, "tool_hits": sorted(tool_hits)}


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
        tool_use = {}
        tf = root / "tool_use.json"
        if tf.exists():
            tool_use = json.loads(tf.read_text())
        for rid in sorted(by_run):
            if rid in done or rid not in targets:
                continue
            a, tpath = by_run[rid]
            out.append(P8.build_row(targets[rid], rid, root / rid, a, tpath, trap_hits))
            tool_use[rid] = a["tool_hits"]
        with open(P8.RESULTS, "a", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        tf.write_text(json.dumps(tool_use, indent=1))
        (root / "audit_r1.json").write_text(json.dumps(audits, indent=1))
        R.arm_trap()
    finally:
        R.lock()
    print(json.dumps([[r["challenge_id"], r["bucket"], r["failure_kind"], r["n_exp"],
                       r["transcript_clean"], by_run[r["run_id"]][0]["tool_hits"]]
                      for r in out] + [{"trap_hits": trap_hits}]))


def _rows(config):
    _select(config)
    return c0r._read_jsonl(P38_ROOT / CONFIGS[config]["dir"] / "results.jsonl")


def _tooluse(config):
    tf = P38_ROOT / CONFIGS[config]["dir"] / "tool_use.json"
    return json.loads(tf.read_text()) if tf.exists() else {}


def report():
    # Phase-16a baseline buckets (for context only; the paired measure is c0-vs-c1 here).
    # These dirs are chmod-000 while another runner holds the vault lock -> tolerate that.
    base = {}
    try:
        for r in c0r._read_jsonl(BASELINE / "results.jsonl") + c0r._read_jsonl(P14_ROOT / "results.jsonl"):
            if r["challenge_id"] in TARGETS and r["challenge_id"] not in base:
                base[r["challenge_id"]] = {"bucket": r["bucket"], "give_up": r.get("give_up")}
    except (PermissionError, FileNotFoundError):
        base = {}  # baseline locked/absent; report the paired c0-vs-c1 result without it

    rows = {c: {r["challenge_id"]: r for r in _rows(c)} for c in CONFIGS}
    tu = {c: _tooluse(c) for c in CONFIGS}
    rid_for = {c: {cid: f"{CONFIGS[c]['prefix']}-r1-{cid}" for cid in TARGETS} for c in CONFIGS}

    table = []
    for cid in TARGETS:
        c0r_ = rows["c0"].get(cid)
        c1r_ = rows["c1"].get(cid)
        c0_solved = bool(c0r_ and c0r_["bucket"] == "SOLVED")
        c1_solved = bool(c1r_ and c1r_["bucket"] == "SOLVED")
        verdict = ("PENDING" if (c0r_ is None or c1r_ is None) else
                   "C1_CONVERTED" if (c1_solved and not c0_solved) else
                   "BOTH_SOLVED" if (c0_solved and c1_solved) else
                   "C1_REGRESSED" if (c0_solved and not c1_solved) else
                   "NEITHER")
        c1_tools = tu["c1"].get(rid_for["c1"][cid], [])
        table.append({
            "cid": cid, "name": NAMES[cid],
            "baseline_16a": base.get(cid, {}).get("bucket"),
            "c0": {"bucket": (c0r_ or {}).get("bucket"), "n_exp": (c0r_ or {}).get("n_exp"),
                   "failure_kind": (c0r_ or {}).get("failure_kind"),
                   "give_up": (c0r_ or {}).get("give_up"),
                   "tokens_output": ((c0r_ or {}).get("tokens") or {}).get("output")},
            "c1": {"bucket": (c1r_ or {}).get("bucket"), "n_exp": (c1r_ or {}).get("n_exp"),
                   "failure_kind": (c1r_ or {}).get("failure_kind"),
                   "give_up": (c1r_ or {}).get("give_up"),
                   "tokens_output": ((c1r_ or {}).get("tokens") or {}).get("output"),
                   "tools_used": c1_tools},
            "verdict": verdict,
            # tool->conversion attribution: only meaningful on a C1_CONVERTED row
            "tool_attributed_conversion": (
                verdict == "C1_CONVERTED" and bool(c1_tools)),
        })

    all_rows = [r for c in CONFIGS for r in _rows(c)]
    rep = {
        "probe": "Phase 38 — Pwn C0 vs C1+tools (cheatsheet + pwndbg/angr/ropper, image 0.3), "
                 "paired x1 on heap_hard subset (5)",
        "configs": {c: CONFIGS[c]["lever"] for c in CONFIGS},
        "budget": CONFIGS["c0"]["budget"],
        "conversion_table": table,
        "summary": {
            "n_targets": len(TARGETS),
            "c0_solved": sum(1 for t in table if t["c0"]["bucket"] == "SOLVED"),
            "c1_solved": sum(1 for t in table if t["c1"]["bucket"] == "SOLVED"),
            "c1_converted": [t["cid"] for t in table if t["verdict"] == "C1_CONVERTED"],
            "both_solved": [t["cid"] for t in table if t["verdict"] == "BOTH_SOLVED"],
            "neither": [t["cid"] for t in table if t["verdict"] == "NEITHER"],
            "c1_regressed": [t["cid"] for t in table if t["verdict"] == "C1_REGRESSED"],
            "pending": [t["cid"] for t in table if t["verdict"] == "PENDING"],
            "tool_conversions": {t["cid"]: t["c1"]["tools_used"]
                                 for t in table if t["verdict"] == "C1_CONVERTED"},
        },
        "note": ("pwndbg is the measured tool (heap_hard = its domain). angr is image/router "
                 "capability insurance; this subset is not angr-shaped so angr has no measured "
                 "conversion here (see store/p38_pwn/trace.json for its sanity check). "
                 "pop_goes_the_printer's essential gap is ObjC decompilation, not heap tooling. "
                 "No performance claim; contaminated/shared NYU bench."),
        "integrity": {
            "fws_total": sum(r["verdict"] == verifier.FLAG_WITHOUT_SOLUTION for r in all_rows),
            "non_container_total": sum(r.get("non_container_exps", 0) for r in all_rows),
            "trap_hits_any": sorted({h for r in all_rows for h in (r.get("batch_trap_hits") or [])}),
            "transcripts_nonclean": [r["run_id"] for r in all_rows
                                     if r.get("transcript_clean") is False],
        },
    }
    P38_ROOT.mkdir(parents=True, exist_ok=True)
    (P38_ROOT / "report.json").write_text(json.dumps(rep, indent=1))
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
