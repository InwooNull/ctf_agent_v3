"""Phase 34 integration rehearsal — the whole agent on a mixed real holdout, REAL LLM solving.

The session (not this script) spawns a real sub-agent per challenge to drive the category CLI;
this runner is the orchestration + policy + submission layer around those real solves:

  fetch/register -> Scheduler(flags-per-hour) -> per-challenge StopLoss (give-up/exhaust = 손절) ->
  [real sub-agent solves blind on the category CLI] -> verify (scorer + CLI-only audit, 3-bucket) ->
  triage decoy screen -> reproduce-before-submit (clean no-history replay of the WINNING experiment) ->
  SubmitGate -> mock_ctfd.

Blind/isolation/anti-cheat are inherited from the per-category harness + the vault lock + the CLI-only
transcript audit, exactly as in the per-category C0 baselines. No live competition (platform = mock_ctfd).
No performance claim — small, mixed, sanity integration.

  python3 eval/p34_rehearsal.py prepare <category>
  python3 eval/p34_rehearsal.py verify  <category> <transcript.jsonl>...
  python3 eval/p34_rehearsal.py submit  <category>        # policy+reproduce+SubmitGate->mock_ctfd
  python3 eval/p34_rehearsal.py report
  python3 eval/p34_rehearsal.py lock|unlock|lockstate <category>

Reuses eval/p8_runner.py (classification/verifier/build_row) + eval/c0b_runner.py (lock/atime-trap/
CLI audit), like eval/p22_misc_runner.py. Batched + resumable (verify/submit skip already-done cids).
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

sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator.scheduler import Scheduler                       # noqa: E402
from orchestrator import triage                                    # noqa: E402
from connector.submit_gate import (                                # noqa: E402
    SubmitGate, DecoyRejected, ReproductionFailed, NotAuthorized, UnverifiedCandidate,
)
from schemas.records import Candidate                              # noqa: E402

P34_ROOT = PROJECT_ROOT / "store" / "p34_rehearsal"
CLASSIFICATION = PROJECT_ROOT / "store" / "p18_misc" / "classification.json"

# The mixed holdout set (fresh p34 run_ids). score/difficulty/est_cost drive the Scheduler; a decoy is
# included on purpose (showdown ships "THIS IS A SAMPLE FLAG"). pwn/rev batches extend this later.
SET = {
    "misc": {
        "cli": "arena/misc_cli.py", "prefix": "p34c0", "cid_re": "mr_[0-9a-f]{6}",
        "arena": "real_misc", "keys": "scorer_keys_misc_real",
        "budget": {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90},
        "image": "ctfagent-misc:0.1",
        "challenges": [
            {"cid": "mr_73bb9c", "score": 100, "difficulty": "easy", "est_cost": 1.0},  # leaked_flag
            {"cid": "mr_993d5a", "score": 90, "difficulty": "med", "est_cost": 1.0},    # simple-recovery
            {"cid": "mr_d3cca3", "score": 80, "difficulty": "med", "est_cost": 1.0},    # showdown (DECOY)
        ],
    },
    "pwn": {
        "cli": "arena/pwn_cli.py", "prefix": "p34pw", "cid_re": "rp_[0-9a-f]{6}",
        "arena": "real_pwn", "keys": "scorer_keys_pwn_real",
        "budget": {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60},
        "image": "ctfagent-pwn:0.1",
        "challenges": [
            {"cid": "rp_deff37", "score": 100, "difficulty": "easy", "est_cost": 1.0},  # baby_boi (16a SOLVED)
            {"cid": "rp_409375", "score": 90, "difficulty": "med", "est_cost": 1.0},    # WarmUp
            {"cid": "rp_84e8fd", "score": 80, "difficulty": "hard", "est_cost": 1.0},   # horrorscope (P33 deployable)
        ],
    },
    "rev": {   # NOTE: synthetic Phase-8 rev set (arena/rev_instances) — the real rev holdout (rr_*) is
               # not keyed; this is a 3rd-harness INTEGRATION check only (synthetic, high contamination).
        "cli": "arena/rev_cli.py", "prefix": "p34rv", "cid_re": "r7_[0-9a-f]{6}",
        "arena": "rev_instances", "keys": "scorer_keys_rev",
        "budget": {"max_experiments": 8, "wall_s": 900, "exp_timeout_s": 30},
        "image": "ctfagent-rev:0.1",
        "challenges": [
            {"cid": "r7_099e2f", "score": 100, "difficulty": "easy", "est_cost": 1.0},
            {"cid": "r7_0b1253", "score": 90, "difficulty": "med", "est_cost": 1.0},
        ],
    },
}
BASE_SECRETS = ["vault", "eval/scorer_keys", "eval/packs", "eval/make_dev_set.py",
                "eval/make_dev_challenge.py", "store/c0", "store/runs", "store/c0b", "store/c0b2",
                "store/p6_c0", "store/p8_c0", "store/p10_c0", "store/p14_c0", "store/p16a_c0",
                "store/p22_misc", "store/p23_pwn", "store/p31_pwn"]


def _cids(cat):
    return [c["cid"] for c in SET[cat]["challenges"]]


def _targets(cat):
    out = []
    for c in SET[cat]["challenges"]:
        out.append({"id": c["cid"], "rep": 1, "subtype": cat,
                    "difficulty": c["difficulty"], "nyu_id": c["cid"]})
    return out


def _select(cat):
    cfg = SET[cat]
    root = P34_ROOT / cat
    root.mkdir(parents=True, exist_ok=True)
    conf = {"config": "P34", "category": cat, "loop": "single ReAct", "prompt_pack": False,
            "experience_store": False, "attempts_per_run": 1, "image": cfg["image"],
            "inspect_first": "prompt + e01 not citable", "boundary": "per-category harness"}
    P8.ROOT, P8.RESULTS = root, root / "results.jsonl"
    P8.ARENA, P8.KEYS = PROJECT_ROOT / "arena" / cfg["arena"], R.VAULT / cfg["keys"]
    P8.CONFIG, P8.BUDGET = conf, cfg["budget"]
    P8._manifest_reps = lambda: _targets(cat)
    P8.run_id_for = lambda m: f"{cfg['prefix']}-r{m['rep']}-{m['id']}"
    R.ROOT, R.RESULTS, R.LOCKFILE, R.TRAPFILE = root, root / "results.jsonl", root / "lock.json", root / "trap.json"
    sibling = [f"store/p34_rehearsal/{c}" for c in SET if c != cat]
    R.STATIC_SECRETS = P8.STATIC_SECRETS = BASE_SECRETS + sibling
    R.CLI_RE = re.compile(rf"^cd ~/ctf_agent_v3 && python3 {re.escape(cfg['cli'])} "
                          rf"({cfg['prefix']}-r(\d+)-{cfg['cid_re']}) (info|exp|report|give_up|status)\b(.*)$")
    return cfg, root


def prepare(cat):
    cfg, root = _select(cat)
    R.unlock()
    try:
        made = []
        for m in _targets(cat):
            cid, rid = m["id"], P8.run_id_for(m)
            d = root / rid
            if d.exists():
                made.append(rid + " (exists)")
                continue
            d.mkdir(parents=True)
            (d / "session.json").write_text(json.dumps(
                {"run_id": rid, "challenge_id": cid, "rep": 1,
                 "challenge_dir": str(P8.ARENA / cid), "status": "OPEN", "exp_count": 0,
                 "experiments": [], "started_at": None, **P8.CONFIG}, indent=2, sort_keys=True))
            if cat == "pwn":                       # 2-uid boundary needs the flag booted to the service
                bf = root / "_boot" / rid
                bf.mkdir(parents=True, exist_ok=True)
                (bf / "flag").write_text(json.loads((P8.KEYS / f"{cid}.json").read_text())["flag"])
                (bf / "flag").chmod(0o600)
            made.append(rid)
        n = R.arm_trap()
    finally:
        R.lock()
    print(json.dumps({"category": cat, "runs": made, "trap_files": n, "locked": R.LOCKFILE.exists()}))


# ---- CLI-only audit (quote-aware; mirrors p22) ------------------------------
_HEREDOC = re.compile(r"<<-?\s*'?\"?([A-Za-z_][A-Za-z0-9_]*)'?\"?\s*$")


def _tail_ok(tail):
    if "$(" in tail or "`" in tail:
        return False, None
    delim = None
    m = _HEREDOC.search(tail)
    if m:
        delim = m.group(1); tail = tail[:m.start()]
    lx = shlex.shlex(tail, posix=True, punctuation_chars=True); lx.whitespace_split = True
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


def verify(cat, transcripts):
    cfg, root = _select(cat)
    R.audit_transcript = _audit
    R.unlock()
    try:
        trap_hits = R.check_trap()
        audits = [_audit(t, 1) for t in transcripts]
        by_run = {rid: (a, t) for a, t in zip(audits, transcripts) for rid in a["run_ids"]}
        done = {r["run_id"] for r in c0r._read_jsonl(P8.RESULTS)}
        targets = {P8.run_id_for(m): m for m in _targets(cat)}
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


# ---- reproduce-before-submit: clean, history-free replay of the WINNING experiment -------------
def _winning_code(run_dir, cid, exp_id):
    """The python code of the experiment the agent cited as evidence (run_dir/work/<name>/<name>.py)."""
    name = exp_id[len(cid) + 1:] if exp_id.startswith(cid + "-") else exp_id
    # the CLI nests the harness store under <run_dir>/harness/; misc stores code at work/<name>/<name>.py,
    # pwn persists it at exp_code/<name>.py (the boundary overwrites work/exp.py each run).
    for p in (run_dir / "harness" / "exp_code" / f"{name}.py",
              run_dir / "harness" / "work" / name / f"{name}.py",
              run_dir / "work" / name / f"{name}.py",
              run_dir / "harness" / "work" / f"{name}.py",
              run_dir / "work" / f"{name}.py"):
        if p.is_file():
            return p.read_text()
    return None


def _reproduce_misc(cid, code, expected_flag, image):
    """Re-run the winning code in a FRESH MiscHarness (no prior history) and require the flag to
    reappear in its container stdout. Returns {"ok", "flag"}."""
    from solver.misc_harness import MiscHarness
    import tempfile
    store = Path(tempfile.mkdtemp())
    h = MiscHarness(f"repro_{cid}", P8.ARENA / cid, store_root=store, image=image)
    out = h.run_experiment({"name": "repro", "code": code, "timeout": 90})
    ok = out.execution_status in ("ok", "error", "timeout") and expected_flag in (out.stdout or "")
    return {"ok": bool(ok), "flag": expected_flag if ok else None}


def _reproduce_pwn(cid, code, expected_flag, image):
    """Replay the winning exploit in a FRESH 2-uid boundary (flag re-staged) and require the flag to
    reappear in the agent's output — a clean, history-free re-derivation over the service."""
    from solver import pwn_deploy
    from tools import pwn_service
    import tempfile
    ch = json.loads((P8.ARENA / cid / "challenge.json").read_text())
    dep = Path(tempfile.mkdtemp()) / "d"
    m = pwn_deploy.resolve(P8.ARENA / cid, dep, challenge=ch)
    run = Path(tempfile.mkdtemp()) / "run"
    run.mkdir(parents=True)
    res = pwn_service.run(run, dep, m["target_rel"].rsplit("/", 1)[-1], expected_flag, code,
                          manifest=m, image=image, wall_s=120, write_record=False)
    ok = res["execution_status"] in ("ok", "error", "timeout") and expected_flag in (res.get("stdout") or "")
    return {"ok": bool(ok), "flag": expected_flag if ok else None}


def _reproduce_rev(cid, code, expected_flag, image):
    from solver.rev_harness import RevHarness
    import tempfile
    h = RevHarness(f"repro_{cid}", P8.ARENA / cid, store_root=Path(tempfile.mkdtemp()), image=image)
    out = h.run_experiment({"name": "repro", "code": code, "timeout": 60})
    ok = out.execution_status in ("ok", "error", "timeout") and expected_flag in (out.stdout or "")
    return {"ok": bool(ok), "flag": expected_flag if ok else None}


REPRODUCE = {"misc": _reproduce_misc, "pwn": _reproduce_pwn, "rev": _reproduce_rev}


def _reported(root, rid):
    s = json.loads((root / rid / "session.json").read_text())
    return s.get("reported")


def submit(cat):
    from connector.ctfd_client import CTFdClient
    from connector.mock_ctfd import MockCTFd, VALID_USER
    cfg, root = _select(cat)
    R.unlock()                      # read scorer-verified rows + challenge flags (orchestrator side)
    try:
        rows = {r["challenge_id"]: r for r in c0r._read_jsonl(P8.RESULTS)}
        sched = Scheduler([{"id": c["cid"], "score": c["score"], "difficulty": c["difficulty"],
                            "est_cost": c["est_cost"]} for c in SET[cat]["challenges"]],
                          global_caps={"experiments": 10 ** 6, "time_s": 10 ** 9})
        order = sched.order_of_attempt()
        cid_to_id = {c["cid"]: i + 1 for i, c in enumerate(SET[cat]["challenges"])}
        # mock platform knows the real flag only for the challenges we will actually submit
        flags = {}
        plan = []
        for cid in order:
            r = rows.get(cid)
            rep = _reported(root, P8.run_id_for({"id": cid, "rep": 1})) if r else None
            plan.append((cid, r, rep))
            if r and r["bucket"] == "SOLVED" and rep and not triage.is_decoy(rep["value"], rep.get("evidence_refs")):
                flags[cid_to_id[cid]] = rep["value"]
        events, pipeline = [], []
        srv = MockCTFd(flags=flags,
                       challenges=[{"id": cid_to_id[c], "name": c, "category": cat, "value": 100,
                                    "solved_by_me": False} for c in _cids(cat)])
        srv.__enter__()
        try:
            client = CTFdClient(srv.base_url, name=VALID_USER["name"],
                                password=VALID_USER["password"], sleep=lambda s: None)
            def _rep_fn(ctfd_id, cand):
                cid = next(c for c, i in cid_to_id.items() if i == ctfd_id)
                code = _winning_code(root / P8.run_id_for({"id": cid, "rep": 1}), cid, cand.evidence_refs[0])
                if not code:
                    return {"ok": False, "flag": None}
                return REPRODUCE[cat](cid, code, cand.value, cfg["image"])
            gate = SubmitGate.for_orchestrator(client, log_path=root / "submissions.jsonl",
                                               decoy_check=triage.is_decoy, reproducer=_rep_fn)
            # governance probe: a sub-agent gate cannot submit, even here
            sub_blocked = False
            try:
                SubmitGate.for_subagent(log_path=root / "_sub.jsonl").submit_flag_value("x", "y")
            except NotAuthorized:
                sub_blocked = True
            for cid, r, rep in plan:
                cidr = {"cid": cid, "bucket": (r or {}).get("bucket"), "reported": bool(rep)}
                if not rep:
                    cidr["result"] = "no_candidate"; events.append(f"[{cid}] no candidate ({cidr['bucket']})")
                    pipeline.append(cidr); continue
                if triage.is_decoy(rep["value"], rep.get("evidence_refs")):
                    cidr["result"] = "decoy_rejected"; events.append(f"[{cid}] triage: DECOY rejected (not submitted)")
                    pipeline.append(cidr); continue
                status_c = "VERIFIED" if r and r["bucket"] == "SOLVED" else "UNVERIFIED"
                cand = Candidate(value=rep["value"], confidence=0.9,
                                 evidence_refs=rep.get("evidence_refs") or [], status=status_c)
                try:
                    st, _ = gate.submit_candidate(cid_to_id[cid], cand)
                    cidr["result"] = f"submitted:{st}"; events.append(f"[{cid}] reproduced+submitted -> {st}")
                except DecoyRejected:
                    cidr["result"] = "decoy_rejected"; events.append(f"[{cid}] DECOY rejected")
                except ReproductionFailed:
                    cidr["result"] = "reproduction_failed"; events.append(f"[{cid}] reproduce gate BLOCKED submit")
                except UnverifiedCandidate:
                    cidr["result"] = "unverified_blocked"; events.append(f"[{cid}] unverified (FAILED) -> not submitted")
                pipeline.append(cidr)
            attempts = sorted(c for c, _ in srv.state.attempts)
        finally:
            srv.__exit__(None, None, None)
        R.arm_trap()
    finally:
        R.lock()
    out = {"category": cat, "scheduler_order": order, "subagent_submit_blocked": sub_blocked,
           "mock_ctfd_scored_ids": attempts, "pipeline": pipeline, "events": events}
    (root / "submit_report.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
    return out


def report(quiet=False):
    cats = [c for c in SET if (P34_ROOT / c / "results.jsonl").exists()]
    allrows, firings, buckets = [], [], {"SOLVED": 0, "FAILED": 0, "BLOCKED": 0}
    per = {}
    for cat in cats:
        _select(cat)
        rows = c0r._read_jsonl(P34_ROOT / cat / "results.jsonl")
        sr = P34_ROOT / cat / "submit_report.json"
        sub = json.loads(sr.read_text()) if sr.is_file() else {}
        for r in rows:
            buckets[r["bucket"]] = buckets.get(r["bucket"], 0) + 1
        per[cat] = {
            "n": len(rows),
            "by_bucket": {b: sum(1 for r in rows if r["bucket"] == b) for b in ("SOLVED", "FAILED", "BLOCKED")},
            "by_subtype": {},
            "scheduler_order": sub.get("scheduler_order"),
            "pipeline": sub.get("pipeline"), "events": sub.get("events"),
            "mock_ctfd_scored_ids": sub.get("mock_ctfd_scored_ids"),
            "subagent_submit_blocked": sub.get("subagent_submit_blocked"),
            "fws": sum(r["verdict"] == verifier.FLAG_WITHOUT_SOLUTION for r in rows),
            "non_container_execs": sum(r.get("non_container_exps", 0) for r in rows),
            "transcripts_nonclean": sorted(r["run_id"] for r in rows if r.get("transcript_clean") is False),
            "trap_hits": sorted({h for r in rows for h in (r.get("batch_trap_hits") or [])}),
            "tokens_out": [((r.get("tokens") or {}).get("output")) for r in rows],
        }
        for r in rows:
            per[cat]["by_subtype"].setdefault(r["subtype"], {"SOLVED": 0, "FAILED": 0, "BLOCKED": 0})
            per[cat]["by_subtype"][r["subtype"]][r["bucket"]] += 1
        allrows += rows
        firings += (sub.get("events") or [])
    rep = {"phase": "P34 integration rehearsal (real LLM, mixed holdout)",
           "note": "mock_ctfd platform; small sanity integration; no performance claim",
           "buckets_overall": buckets, "per_category": per, "policy_firings": firings,
           "integrity": {"fws_total": sum(p["fws"] for p in per.values()),
                         "non_container_total": sum(p["non_container_execs"] for p in per.values()),
                         "transcripts_nonclean": [r for p in per.values() for r in p["transcripts_nonclean"]]}}
    P34_ROOT.mkdir(parents=True, exist_ok=True)
    (P34_ROOT / "report.json").write_text(json.dumps(rep, indent=1))
    if not quiet:                       # a wrapper (p36_runner) prints its own augmented rep once
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
    elif cmd == "submit":
        submit(argv[1])
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

