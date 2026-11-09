"""Phase 5b C0 runner: structural blindness (lock), sessions, audit, verify, aggregate.

  python3 eval/c0b_runner.py prepare <rep>                     # unlock -> sessions -> arm trap -> lock
  python3 eval/c0b_runner.py verify <rep> <transcript.jsonl>... # unlock -> trap/transcript audit -> verifier -> lock
  python3 eval/c0b_runner.py report                            # aggregate store/c0b/results.jsonl
  python3 eval/c0b_runner.py lock | unlock | lockstate

Prevention (not just detection): while solve sessions run, every secret or
solution-bearing path is chmod 000 — vault/ (generator, reference solvers,
manifest, scorer keys), the Phase 3-5 keys/generators/runs, and finished c0b
runs. Solve sessions only ever see arena/ (public instances + CLI) and their own
store/c0b/<run_id>/. The atime trap and transcript audit run on top of that.

Tokens per agent are read from the harness's subagent transcripts (assistant
message usage, deduplicated by message id) — measured, not estimated.
"""
import importlib.util
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import verifier  # noqa: E402

_spec = importlib.util.spec_from_file_location("c0_runner", PROJECT_ROOT / "eval" / "c0_runner.py")
c0r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c0r)

VAULT = PROJECT_ROOT / "vault"
ARENA = PROJECT_ROOT / "arena" / "instances"
# P5B_SET=v1 (default) -> store/c0b, vault/manifest.json ; P5B_SET=v2 -> store/c0b2, vault/manifest_v2.json
SET = os.environ.get("P5B_SET", "v1")
ROOT = PROJECT_ROOT / "store" / {"v1": "c0b", "v2": "c0b2"}[SET]
MANIFEST = VAULT / {"v1": "manifest.json", "v2": "manifest_v2.json"}[SET]
RUN_PREFIX = {"v1": "c0b", "v2": "c0b2"}[SET]
RESULTS = ROOT / "results.jsonl"
LOCKFILE = ROOT / "lock.json"
TRAPFILE = ROOT / "trap.json"
SENTINEL = 1_000_000_000.0
BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 30}
C0_CONFIG = dict(c0r.C0_CONFIG)

STATIC_SECRETS = ["vault", "store/c0", "store/runs", "eval/scorer_keys",
                  "eval/make_dev_set.py", "eval/make_dev_challenge.py"] + (["store/c0b"] if SET == "v2" else [])


def run_id_for(m):
    return f"{RUN_PREFIX}-r{m['rep']}-{m['id']}"


def _read_jsonl(p):
    return c0r._read_jsonl(p)


def _verified_run_dirs():
    return [f"{ROOT.relative_to(PROJECT_ROOT)}/{r['run_id']}" for r in _read_jsonl(RESULTS)]


# ---- lock -------------------------------------------------------------------

def lock():
    if LOCKFILE.exists():
        return
    modes = {}
    for rel in STATIC_SECRETS + _verified_run_dirs():
        p = PROJECT_ROOT / rel
        if p.exists():
            modes[rel] = stat.S_IMODE(p.stat().st_mode)
            os.chmod(p, 0)
    LOCKFILE.write_text(json.dumps(modes, indent=1))


def unlock():
    if not LOCKFILE.exists():
        return
    for rel, mode in json.loads(LOCKFILE.read_text()).items():
        os.chmod(PROJECT_ROOT / rel, mode)
    LOCKFILE.unlink()


# ---- atime trap (detection, on top of the lock) ------------------------------

def _trap_targets():
    out = []
    for rel in STATIC_SECRETS + _verified_run_dirs():
        p = PROJECT_ROOT / rel
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += [f for f in p.rglob("*") if f.is_file()]
    return sorted(set(out))


def arm_trap():
    armed = {}
    for p in _trap_targets():
        os.utime(p, (SENTINEL, max(p.stat().st_mtime, time.time())))
        armed[str(p.relative_to(PROJECT_ROOT))] = SENTINEL
    TRAPFILE.write_text(json.dumps({"armed_at": time.time(), "files": armed}))
    return len(armed)


def check_trap():
    if not TRAPFILE.exists():
        return ["<trap never armed>"]
    st = json.loads(TRAPFILE.read_text())
    return [rel for rel, s in st["files"].items()
            if (PROJECT_ROOT / rel).exists() and (PROJECT_ROOT / rel).stat().st_atime != s]


# ---- pre-spawn blind guard (prior same-CID run dirs + cleartext-flag files) ----
# Finding P51: the vault lock only covers the STATIC_SECRETS tree. A PRIOR run
# directory of the SAME challenge id, living in another phase's store/ dir, is NOT
# in that tree, so a freshly spawned blind solver could read a past transcript (and
# any cleartext candidate flag beside it) of its OWN challenge. That destroys blind
# independence. Every cycle must remove those from solver visibility BEFORE spawning.
# This guard is pure strengthen (chmod 0 only) + restorable, so it never weakens the
# vault and the auto-mode safety classifier allows it (unlike repair()'s chmod-up).

_REAL_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[0-9a-fA-F]{16,}\}")


def prior_cid_run_dirs(cids, cycle_root):
    """Shallowest run directories outside cycle_root whose name carries one of the
    given challenge ids (a past solve of the solver's own challenge)."""
    cycle_root = Path(cycle_root).resolve()
    found = []
    for d in (PROJECT_ROOT / "store").rglob("*"):
        try:
            if not d.is_dir():
                continue
        except OSError:
            continue
        if d.resolve() == cycle_root or cycle_root in d.resolve().parents:
            continue
        if any(c in d.name for c in cids):
            found.append(d.resolve())
    found = sorted(set(found), key=lambda p: len(p.parts))
    shallow = []
    for d in found:
        if not any(a in d.parents for a in shallow):
            shallow.append(d)
    return sorted(shallow, key=str)


def _cleartext_flag_files(sibling_dirs):
    """Loose files sitting directly in the contaminating sibling store dirs that carry a
    REAL cleartext flag value (flag{<16+ hex>}), e.g. a runs_*.json candidate dump."""
    out = []
    for sd in sibling_dirs:
        if not sd.is_dir():
            continue
        for f in sd.iterdir():
            try:
                if not f.is_file() or f.stat().st_size > 8_000_000:
                    continue
                if _REAL_FLAG_RE.search(f.read_text(errors="replace")):
                    out.append(f.resolve())
            except OSError:
                continue
    return sorted(set(out), key=str)


def guard_prespawn(cids, cycle_root, extra_hygiene=()):
    """STANDARD PRE-SPAWN BLIND GUARD. chmod-0 (a) every prior same-CID run dir outside
    cycle_root, (b) loose cleartext-flag files beside them, (c) explicit extra_hygiene
    paths. Records true modes in cycle_root/prespawn_guard.json for unguard_prespawn().
    Idempotent (re-runs never overwrite a recorded true mode with 0)."""
    cycle_root = Path(cycle_root)
    gf = cycle_root / "prespawn_guard.json"
    recorded = json.loads(gf.read_text()) if gf.is_file() else {}
    dirs = prior_cid_run_dirs(cids, cycle_root)
    siblings = sorted({d.parent for d in dirs})
    targets = list(dirs) + _cleartext_flag_files(siblings)
    for p in extra_hygiene:
        p = Path(p) if Path(p).is_absolute() else (PROJECT_ROOT / p)
        if p.exists():
            targets.append(p.resolve())
    targets = sorted(set(targets), key=str)
    for p in targets:
        rel = str(p.relative_to(PROJECT_ROOT))
        if rel not in recorded:                       # keep the TRUE mode across idempotent re-runs
            recorded[rel] = stat.S_IMODE(p.stat().st_mode)
        os.chmod(p, 0)
    gf.write_text(json.dumps(recorded, indent=1, sort_keys=True))
    return {"guarded": len(targets), "run_dirs": len(dirs),
            "cleartext_files": len(targets) - len(dirs),
            "paths": [str(p.relative_to(PROJECT_ROOT)) for p in targets]}


def unguard_prespawn(cycle_root):
    """Restore everything guard_prespawn locked (shallowest first) and drop the record."""
    gf = Path(cycle_root) / "prespawn_guard.json"
    if not gf.is_file():
        return {"restored": 0}
    rec = json.loads(gf.read_text())
    for rel in sorted(rec, key=lambda r: len(Path(r).parts)):
        p = PROJECT_ROOT / rel
        if p.exists():
            os.chmod(p, rec[rel])
    gf.unlink()
    return {"restored": len(rec)}


# ---- transcripts: audit + tokens ---------------------------------------------

CLI_RE = re.compile(r"^cd ~/ctf_agent_v3 && python3 arena/c0b_cli\.py (c0b2?-r(\d+)-p5b_[0-9a-f]{6}) "
                    r"(info|exp|report|give_up|status)\b(.*)$")
BAD_TAIL = re.compile(r"[;|`>]|&&|\$\(")
SHELL_OPS = {";", "&&", "||", "|", "&", ">", ">>", "<", "<<<", ">&", "<&"}


def _tail_ok(tail):
    """Quote-aware: reject shell operators outside quotes; allow one trailing <<'EOF' heredoc.
    Command substitution ($( or backtick) is rejected anywhere, since it expands inside double quotes."""
    if "$(" in tail or "`" in tail:
        return False
    import shlex
    lx = shlex.shlex(tail, posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try:
        toks = list(lx)
    except ValueError:                  # unbalanced quotes
        return False
    if toks[-2:] == ["<<", "EOF"]:
        toks = toks[:-2]
    return not any(t in SHELL_OPS or t == "<<" for t in toks)


def audit_transcript(path, rep):
    calls, bad, rids, seen, tok_in, tok_out = 0, [], set(), set(), 0, 0
    tok = {"input_uncached": 0, "cache_creation": 0, "cache_read": 0, "output": 0}
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
            m = CLI_RE.match(first) if b.get("name") == "Bash" else None
            tail = m.group(4) if m else ""
            multiline_ok = "\n" not in cmd or cmd.rstrip().endswith("\nEOF")
            if m and int(m.group(2)) == rep and _tail_ok(tail) and multiline_ok:
                rids.add(m.group(1))
            else:
                bad.append({"tool": b.get("name"), "first_line": first[:200]})
    return {"transcript": str(path), "tool_calls": calls, "run_ids": sorted(rids), "nonconforming": bad,
            "clean": not bad and len(rids) == 1, "tokens_in": tok_in, "tokens_out": tok_out,
            "tokens_total": tok_in + tok_out, "tokens_breakdown": tok}


# ---- commands -----------------------------------------------------------------

def prepare(rep):
    ROOT.mkdir(parents=True, exist_ok=True)
    unlock()
    try:
        man = [m for m in json.loads(MANIFEST.read_text()) if m["rep"] == rep]
        made = []
        for m in man:
            rid = run_id_for(m)
            d = ROOT / rid
            if d.exists():
                raise SystemExit(f"{d} exists")
            d.mkdir(parents=True)
            sess = {"run_id": rid, "challenge_id": m["id"], "rep": rep,
                    "challenge_dir": str(ARENA / m["id"]), "status": "OPEN",
                    "exp_count": 0, "experiments": [], "started_at": None, **C0_CONFIG}
            (d / "session.json").write_text(json.dumps(sess, indent=2, sort_keys=True))
            made.append(rid)
        n = arm_trap()
    finally:
        lock()
    print(json.dumps({"rep": rep, "runs": made, "trap_files": n, "locked": LOCKFILE.exists()}))


def verify_rep(rep, transcripts):
    unlock()
    try:
        trap_hits = check_trap()                         # before anything reads the keys
        audits = [audit_transcript(t, rep) for t in transcripts]
        by_run = {}
        for a in audits:
            for rid in a["run_ids"]:
                by_run[rid] = a
        man = [m for m in json.loads(MANIFEST.read_text()) if m["rep"] == rep]
        done = {r["run_id"] for r in _read_jsonl(RESULTS)}
        out = []
        for m in man:
            rid = run_id_for(m)
            if rid in done:
                raise SystemExit(f"{rid} already verified")
            d = ROOT / rid
            sess = json.loads((d / "session.json").read_text())
            v = verifier.verify(d / "harness", m["id"], scorer_keys_dir=VAULT / "scorer_keys")
            exps = sess["experiments"]
            calls = _read_jsonl(d / "c0_calls.jsonl")
            outcome, kind = c0r._classify(sess, v, exps)
            end = sess.get("ended_at") or (calls[-1]["t"] if calls else None)
            a = by_run.get(rid)
            out.append({
                "run_id": rid, "challenge_id": m["id"], "rep": rep, "family": m["family"],
                "subtype": m["subtype"], "difficulty": m["difficulty"],
                "verdict": v["verdict"], "outcome": outcome, "failure_kind": kind,
                "session_status": sess["status"], "give_up": sess.get("give_up"),
                "n_exp": len(exps),
                "n_exp_ok": sum(e["status"] == "ok" for e in exps),
                "n_exp_error": sum(e["status"] == "error" for e in exps),
                "n_exp_timeout": sum(e["status"] == "timeout" for e in exps),
                "n_exp_aborted": sum(e["status"] == "aborted" for e in exps),
                "non_container_exps": sum(1 for e in exps if e["profile"] != "container" and not e.get("cached")),
                "n_cli_calls": len(calls), "n_cli_errors": sum(not c["ok"] for c in calls),
                "wall_s": round(end - sess["started_at"], 1) if (end and sess.get("started_at")) else None,
                "evidence_exp_id": v.get("evidence_exp_id"),
                "transcript_clean": a["clean"] if a else None,
                "transcript_nonconforming": a["nonconforming"] if a else None,
                "tokens_total": a["tokens_total"] if a else None,
                "tokens_out": a["tokens_out"] if a else None,
                "batch_trap_hits": trap_hits, **C0_CONFIG,
            })
        with open(RESULTS, "a", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        (ROOT / f"audit_r{rep}.json").write_text(json.dumps(audits, indent=1))
    finally:
        lock()                                            # now also covers this rep's runs
    print(json.dumps([[r["run_id"], r["subtype"], r["outcome"], r["n_exp"], r["transcript_clean"]]
                      for r in out] + [{"trap_hits": trap_hits}], indent=0))


def aggregate():
    rows = _read_jsonl(RESULTS)
    rate = c0r._rate

    def by(key):
        return {k: rate([r for r in rows if r[key] == k]) for k in sorted({r[key] for r in rows})}
    per_type = {}
    for st in sorted({r["subtype"] for r in rows}):
        rr = sorted([r for r in rows if r["subtype"] == st], key=lambda r: r["rep"])
        per_type[st] = {"difficulty": rr[0]["difficulty"],
                        "solved_of_instances": f"{sum(r['outcome'] == 'SOLVED' for r in rr)}/{len(rr)}",
                        "per_rep": [r["outcome"] for r in rr], "n_exp_per_rep": [r["n_exp"] for r in rr],
                        "instances": [r["challenge_id"] for r in rr]}
    tot_exp = sum(r["n_exp"] for r in rows)
    tot_ok = sum(r["n_exp_ok"] for r in rows)
    tot_calls = sum(r["n_cli_calls"] for r in rows)
    tot_err = sum(r["n_cli_errors"] for r in rows)
    outcomes, kinds = {}, {}
    for r in rows:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        if r["failure_kind"]:
            kinds[r["failure_kind"]] = kinds.get(r["failure_kind"], 0) + 1
    toks = [r["tokens_total"] for r in rows if r["tokens_total"] is not None]
    # per-component token stats, recomputed from the recorded transcript list of each rep
    comp = {}
    for tf in sorted(ROOT.glob("transcripts_r*.txt")):
        rep_no = int(tf.stem.split("_r")[1])
        for line in tf.read_text().split():
            if Path(line).exists():
                for k, v in audit_transcript(line, rep_no)["tokens_breakdown"].items():
                    comp.setdefault(k, []).append(v)
    overall = rate(rows)
    rep = {
        "config": C0_CONFIG, "budget": BUDGET,
        "sample": {"types": len(per_type), "instances_per_type": 3, "runs": len(rows),
                   "note": "small sample; each rep is a DIFFERENT random instance -> provisional"},
        "solve_rate": {"overall": overall, "by_difficulty": by("difficulty"),
                       "by_family": by("family"), "by_subtype": by("subtype")},
        "headroom": {"in_30_70_band": overall["rate"] is not None and 0.3 <= overall["rate"] <= 0.7,
                     "ceiling": overall["rate"] == 1.0, "floor": overall["rate"] == 0.0},
        "variability": per_type,
        "experiments_per_run": c0r._stats([r["n_exp"] for r in rows]),
        "experiments_per_solved_run": c0r._stats([r["n_exp"] for r in rows if r["outcome"] == "SOLVED"]),
        "wall_s_per_run": c0r._stats([r["wall_s"] for r in rows]),
        "tool_call_validity": {"exp_ok_over_exp": f"{tot_ok}/{tot_exp}",
                               "exp_ok_rate": round(tot_ok / tot_exp, 3) if tot_exp else None,
                               "cli_ok_over_calls": f"{tot_calls - tot_err}/{tot_calls}",
                               "cli_ok_rate": round((tot_calls - tot_err) / tot_calls, 3) if tot_calls else None},
        "flag_without_solution": outcomes.get("FLAG_WITHOUT_SOLUTION", 0),
        "outcomes": outcomes, "failure_kinds_non_solved": kinds,
        "give_up_self_reported": [{"run_id": r["run_id"], **r["give_up"]} for r in rows if r["give_up"]],
        "non_container_executions": sum(r["non_container_exps"] for r in rows),
        "consumption_proxy": {"agent_sessions": len(rows), "experiments": tot_exp, "cli_calls": tot_calls,
                              "wall_s_total": round(sum(r["wall_s"] or 0 for r in rows), 1),
                              "tokens_per_agent": c0r._stats(toks),
                              "tokens_total": sum(toks), "tokens_measured_runs": len(toks),
                              "tokens_note": "tokens_per_agent sums every assistant turn incl. cache reads "
                                             "(context re-read each turn); see tokens_components_per_agent",
                              "tokens_components_per_agent": {k: c0r._stats(v) for k, v in comp.items()}},
        "blindness": {"trap_hits": sorted({h for r in rows for h in r["batch_trap_hits"]}),
                      "transcripts_clean": sum(1 for r in rows if r["transcript_clean"]),
                      "transcripts_missing": sum(1 for r in rows if r["transcript_clean"] is None)},
    }
    (ROOT / "report.json").write_text(json.dumps(rep, indent=2) + "\n")
    (ROOT / "report.md").write_text(_markdown(rep))
    print(json.dumps(rep, indent=2))


def _markdown(rep):
    L = ["# C0 baseline (Phase 5b) — auto-generated by eval/c0b_runner.py", "",
         f"Config: {rep['config']}", f"Budget/run: {rep['budget']}",
         f"Sample: {rep['sample']['runs']} runs = {rep['sample']['types']} types x 3 different random "
         "instances — **small sample, provisional**", "",
         "## Solve rate (SOLVED only)", "", "| group | solved/runs | rate | Wilson 95% |", "|---|---|---|---|"]
    o = rep["solve_rate"]["overall"]
    L.append(f"| overall | {o['solved']}/{o['runs']} | {o['rate']} | {o['wilson95']} |")
    for sect in ("by_difficulty", "by_family", "by_subtype"):
        for k, v in rep["solve_rate"][sect].items():
            L.append(f"| {sect[3:]}={k} | {v['solved']}/{v['runs']} | {v['rate']} | {v['wilson95']} |")
    L += ["", f"Headroom: {rep['headroom']}", "", "## Variability (3 different instances per type)", "",
          "| type | diff | solved | per rep | exps |", "|---|---|---|---|---|"]
    for st, v in rep["variability"].items():
        L.append(f"| {st} | {v['difficulty']} | {v['solved_of_instances']} | {', '.join(v['per_rep'])} | "
                 f"{v['n_exp_per_rep']} |")
    L += ["", "## Other metrics", ""] + [f"- {k}: {rep[k]}" for k in (
        "experiments_per_run", "experiments_per_solved_run", "wall_s_per_run", "tool_call_validity",
        "flag_without_solution", "outcomes", "failure_kinds_non_solved", "give_up_self_reported",
        "non_container_executions", "consumption_proxy", "blindness")] + [""]
    return "\n".join(L)


def main(argv):
    cmd = argv[:1]
    if cmd == ["prepare"] and len(argv) == 2:
        prepare(int(argv[1]))
    elif cmd == ["verify"] and len(argv) >= 3:
        verify_rep(int(argv[1]), argv[2:])
    elif cmd == ["report"]:
        aggregate()
    elif cmd == ["lock"]:
        lock()
    elif cmd == ["unlock"]:
        unlock()
    elif cmd == ["lockstate"]:
        print(json.dumps({"locked": LOCKFILE.exists()}))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
