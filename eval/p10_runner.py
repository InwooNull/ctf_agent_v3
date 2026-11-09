"""Phase 10 runner: C0 on the real NYU CTF Bench Reverse HOLDOUT (18 problems x 3 reps = 54 runs).

  python3 eval/p10_runner.py prepare <rep> [--only rr_xxxxxx,...]   # rep k = one run of every holdout problem;
                                                                    # --only: (re)create just those (problem, rep)
  python3 eval/p10_runner.py verify <rep> <transcript.jsonl>...     # verifies exactly the runs those transcripts drove
  python3 eval/p10_runner.py exclude <run_id> <infra|transcript_dirty|trap_hit> <reason...>
  python3 eval/p10_runner.py report                                 # -> store/p10_c0/report.{json,md} (clean runs only)
  python3 eval/p10_runner.py lock | unlock | lockstate

Reuses eval/p8_runner.py (3-bucket classification, row building, aggregation) and through it
eval/c0b_runner.py (chmod-000 lock, atime trap, CLI-only transcript audit), re-pointed at the
real holdout. While a batch runs, the lock also covers the 8 DEV problem dirs in arena/real_rev,
the Phase 8 store and store/p10_c0/_excluded. Scoring reads only vault/scorer_keys_real.

Integrity filter (outcome-blind; a run is never excluded because of its verdict):
  infra            session still OPEN and the transcript ends in an API error (agent killed by the
                   harness/API, not a model decision)
  transcript_dirty the CLI-only transcript audit is not clean (host tool use outside the CLI)
  trap_hit         the atime trap fired during the batch
Excluded runs are moved (never deleted) to store/p10_c0/_excluded/<run_id>/ with a README and a line in
_excluded/excluded.jsonl; they never get a results row. A (problem, rep) is retried as
p10c0-r<rep>-<id>-a<k>, at most MAX_ATTEMPTS attempts in total. Every re-arm of the trap is preceded by
a trap check, logged to trap_history.jsonl (a hit aborts); every command that reads secrets while unlocked
re-arms the trap before re-locking, so a later check only sees access made after it.
"""
import importlib.util
import json
import re
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("p8_runner", PROJECT_ROOT / "eval" / "p8_runner.py")
P8 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P8)
R, c0r = P8.R, P8.c0r

ROOT = PROJECT_ROOT / "store" / "p10_c0"
EXCL = ROOT / "_excluded"
EXCL_LOG = EXCL / "excluded.jsonl"
TRAP_HISTORY = ROOT / "trap_history.jsonl"
VAULT = R.VAULT
SECRET_CACHE = ROOT / "lock_paths.json"
EXCL_REL = "store/p10_c0/_excluded"
MAX_ATTEMPTS = 3
CRITERIA = ("infra", "transcript_dirty", "trap_hit")
ANCHORS = {"baby's first", "baby's third"}    # flag is plaintext in the shipped file (by original design)
CONFIG = dict(P8.CONFIG, image="ctfagent-rev:0.1", set="NYU CTF Bench rev holdout (offline)",
              inspect_first="prompt + e01 not citable")
BUDGET = {"max_experiments": 10, "wall_s": 1200, "exp_timeout_s": 60}
RUN_RE = re.compile(r"^p10c0-r(\d+)-(rr_[0-9a-f]{6})(?:-a(\d+))?$")

P8.ROOT, P8.RESULTS = ROOT, ROOT / "results.jsonl"
P8.ARENA = PROJECT_ROOT / "arena" / "real_rev"
P8.KEYS = VAULT / "scorer_keys_real"
P8.CONFIG, P8.BUDGET = CONFIG, BUDGET
R.ROOT, R.RESULTS, R.LOCKFILE, R.TRAPFILE = ROOT, P8.RESULTS, ROOT / "lock.json", ROOT / "trap.json"
R.CLI_RE = re.compile(r"^cd ~/ctf_agent_v3 && python3 arena/real_cli\.py "
                      r"(p10c0-r(\d+)-rr_[0-9a-f]{6}(?:-a\d+)?) "
                      r"(info|exp|report|give_up|status)\b(.*)$")


def _secrets():
    """Static lock list. Needs the split (in vault) once; cached so lock() works while vault is locked."""
    ROOT.mkdir(parents=True, exist_ok=True)
    try:
        split = json.loads((VAULT / "split_real.json").read_text())
        paths = P8.STATIC_SECRETS + ["store/p8_c0"] + [f"arena/real_rev/{c}" for c in split["dev"]]
        SECRET_CACHE.write_text(json.dumps(paths))
    except PermissionError:
        paths = json.loads(SECRET_CACHE.read_text())
    return paths + ([EXCL_REL] if EXCL_REL not in paths else [])


def _manifest_reps():
    man = json.loads((VAULT / "manifest_real.json").read_text())
    hold = json.loads((VAULT / "split_real.json").read_text())["holdout"]
    return [{"id": cid, "rep": k, "subtype": man[cid]["name"],
             "difficulty": f"{man[cid]['year']}{'q' if 'Quals' in man[cid]['event'] else 'f'}"}
            for k in (1, 2, 3) for cid in sorted(hold)]


def run_id_for(m, attempt=1):
    return f"p10c0-r{m['rep']}-{m['id']}" + (f"-a{attempt}" if attempt > 1 else "")


def parse_run_id(rid):
    """-> (rep, challenge_id, attempt)"""
    m = RUN_RE.match(rid)
    if not m:
        raise ValueError(f"not a p10 run id: {rid!r}")
    return int(m.group(1)), m.group(2), int(m.group(3) or 1)


P8._manifest_reps = _manifest_reps
P8.run_id_for = run_id_for


# ---- integrity filter (pure; unit-tested) --------------------------------------

def ends_in_api_error(transcript):
    """True iff the last assistant record of a subagent transcript is a harness API-error message."""
    last = None
    with open(transcript, encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") == "assistant":
                last = rec
    return bool(last and last.get("isApiErrorMessage"))


def exclusion_reason(sess, audit, trap_hits, api_error_end):
    """(criterion, detail) or None. Deliberately blind to the verdict: never looks at flags or the verifier."""
    if trap_hits:
        return "trap_hit", f"atime trap fired during the batch: {trap_hits[:5]}"
    if sess.get("status") == "OPEN" and api_error_end:
        return "infra", "session OPEN (no report/give_up) and transcript ends in an API error"
    if audit is None:
        return "transcript_dirty", "no transcript for this run"
    if not audit["clean"]:
        return "transcript_dirty", f"non-CLI tool use: {audit['nonconforming'][:3]}"
    return None


def next_attempt(cid, rep, excluded, active_ids):
    """Attempt number for a fresh (cid, rep) run, or None if one is active / attempts are used up."""
    if any(parse_run_id(r)[:2] == (rep, cid) for r in active_ids):
        return None
    k = 1 + sum(1 for e in excluded if (e["rep"], e["challenge_id"]) == (rep, cid))
    if k > MAX_ATTEMPTS:
        raise SystemExit(f"({cid}, r{rep}): {MAX_ATTEMPTS} attempts used up; not retrying")
    return k


def move_to_excluded(run_dir, excl_root, record, results_row=None):
    """Move a run dir to excl_root/<run_id>/ (never delete) + README + excluded.jsonl line."""
    dest = excl_root / run_dir.name
    if dest.exists():
        raise SystemExit(f"{dest} already exists")
    excl_root.mkdir(parents=True, exist_ok=True)
    shutil.move(str(run_dir), str(dest))
    (dest / "README.md").write_text(
        f"# Excluded run {record['run_id']}\n\n"
        f"- criterion: {record['criterion']}\n- detail: {record['detail']}\n"
        f"- transcript: {record.get('transcript')}\n- excluded_at: {record['excluded_at_iso']}\n"
        f"- rule: excluded on an outcome-blind integrity criterion; not part of any aggregate.\n")
    if results_row is not None:
        (dest / "results_row_removed.json").write_text(json.dumps(results_row, indent=1, sort_keys=True) + "\n")
    with open(excl_root / "excluded.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return dest


def drop_result_row(results, run_id, backup):
    """Remove run_id's row from results.jsonl (original kept at backup). Returns the removed row."""
    lines = results.read_text().splitlines(keepends=True)
    keep = [l for l in lines if l.strip() and json.loads(l)["run_id"] != run_id]
    gone = [json.loads(l) for l in lines if l.strip() and json.loads(l)["run_id"] == run_id]
    if len(gone) != 1:
        raise SystemExit(f"{run_id}: expected exactly one results row, found {len(gone)}")
    shutil.copy2(results, backup)
    tmp = results.with_suffix(".tmp")
    tmp.write_text("".join(keep))
    tmp.replace(results)
    return gone[0]


# ---- state helpers -------------------------------------------------------------

def _excluded():
    return c0r._read_jsonl(EXCL_LOG)


def _verified():
    return {r["run_id"] for r in c0r._read_jsonl(P8.RESULTS)}


def _active_run_ids():
    """Run dirs in store/p10_c0 (not excluded). Needs the lock released for the verified ones' contents,
    but listing the parent is always possible."""
    return sorted(p.name for p in ROOT.iterdir() if p.is_dir() and RUN_RE.match(p.name))


def _live_runs(except_ids=()):
    """Unverified runs that may still have an agent attached: OPEN and not past their wall budget
    (or never started). Unlocking the vault while one is live would break the blind."""
    live, done = [], _verified()
    for rid in _active_run_ids():
        if rid in done or rid in except_ids:
            continue
        sess = json.loads((ROOT / rid / "session.json").read_text())
        if sess["status"] != "OPEN":
            continue
        st = sess.get("started_at")
        if st is None or time.time() - st < BUDGET["wall_s"] + 120:
            live.append(rid)
    return live


def _check_and_log_trap(context):
    hits = R.check_trap()
    with open(TRAP_HISTORY, "a", encoding="utf-8") as f:
        f.write(json.dumps({"t": time.time(), "context": context, "hits": hits}) + "\n")
    if hits:
        raise SystemExit(f"TRAP HIT ({context}): {hits[:10]} -- stopping; blind integrity in doubt")
    return hits


def _rearm(context):
    """Re-arm after this command's own legitimate reads, so the next pre-re-arm check only sees later access."""
    n = R.arm_trap()
    with open(TRAP_HISTORY, "a", encoding="utf-8") as f:
        f.write(json.dumps({"t": time.time(), "context": f"re-arm after {context}", "files": n}) + "\n")
    return n


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# ---- commands --------------------------------------------------------------------

def prepare_only(rep, ids):
    live = _live_runs()
    if live:
        raise SystemExit(f"live runs present, not unlocking: {live}")
    R.unlock()
    try:
        _check_and_log_trap(f"before re-arm: prepare {rep} --only {','.join(ids)}")
        made, skipped = [], []
        try:                                            # re-arm on every exit path after the check (incl. refusals)
            by_id = {m["id"]: m for m in _manifest_reps() if m["rep"] == rep}
            for cid in ids:
                if cid not in by_id:
                    raise SystemExit(f"{cid} is not a holdout problem")
                k = next_attempt(cid, rep, _excluded(), _active_run_ids())
                if k is None:
                    skipped.append(cid)
                    continue
                rid = run_id_for(by_id[cid], k)
                d = ROOT / rid
                d.mkdir(parents=True)
                sess = {"run_id": rid, "challenge_id": cid, "rep": rep, "attempt": k,
                        "challenge_dir": str(P8.ARENA / cid), "status": "OPEN", "exp_count": 0,
                        "experiments": [], "started_at": None, **CONFIG}
                (d / "session.json").write_text(json.dumps(sess, indent=2, sort_keys=True))
                made.append(rid)
        finally:
            n = _rearm(f"prepare {rep} --only {','.join(ids)}")
    finally:
        R.lock()
    print(json.dumps({"rep": rep, "runs": made, "skipped_active": skipped, "trap_files": n,
                      "locked": R.LOCKFILE.exists()}))


def verify(rep, transcripts):
    audits = [R.audit_transcript(t, rep) for t in transcripts]     # transcripts live outside the lock
    targets = {}
    for a, t in zip(audits, transcripts):
        if not a["run_ids"]:
            raise SystemExit(f"{t}: no conforming CLI call for rep {rep}; cannot attribute to a run")
        for rid in a["run_ids"]:
            if rid in targets:
                raise SystemExit(f"{rid} appears in two transcripts")
            targets[rid] = (a, t)
    done, active = _verified(), set(_active_run_ids())
    for rid in targets:
        if rid in done:
            raise SystemExit(f"{rid} already verified")
        if rid not in active:
            raise SystemExit(f"{rid}: no active run dir")
        if parse_run_id(rid)[0] != rep:
            raise SystemExit(f"{rid} is not rep {rep}")
    live = _live_runs(except_ids=targets)
    if live:
        raise SystemExit(f"live runs present, not unlocking: {live}")
    R.unlock()
    try:
        trap_hits = R.check_trap()                      # before anything reads the vault
        with open(TRAP_HISTORY, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": time.time(), "context": f"verify {rep}", "hits": trap_hits}) + "\n")
    except BaseException:
        R.lock()
        raise
    try:
        by_id = {m["id"]: m for m in _manifest_reps() if m["rep"] == rep}
        rows, excl = [], []
        for rid, (a, t) in sorted(targets.items()):
            d = ROOT / rid
            sess = json.loads((d / "session.json").read_text())
            why = exclusion_reason(sess, a, trap_hits, ends_in_api_error(t))
            if why:
                _, cid, k = parse_run_id(rid)
                rec = {"run_id": rid, "challenge_id": cid, "rep": rep, "attempt": k, "criterion": why[0],
                       "detail": why[1], "transcript": str(t), "excluded_at": time.time(),
                       "excluded_at_iso": _now_iso(), "via": "verify"}
                move_to_excluded(d, EXCL, rec)
                excl.append([rid, why[0]])
                continue
            row = P8.build_row(by_id[parse_run_id(rid)[1]], rid, d, a, t, trap_hits)
            row["attempt"] = parse_run_id(rid)[2]
            row["transcript"] = str(t)
            rows.append(row)
        with open(P8.RESULTS, "a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        (ROOT / f"audit_r{rep}_{int(time.time())}.json").write_text(json.dumps(audits, indent=1))
        with open(ROOT / f"transcripts_r{rep}.txt", "a") as f:
            f.write("\n".join(transcripts) + "\n")
    finally:
        try:
            _rearm(f"verify {rep}")
        finally:
            R.lock()
    print(json.dumps([[r["run_id"], r["subtype"], r["bucket"], r["failure_kind"], r["n_exp"]] for r in rows]
                     + [{"excluded": excl, "trap_hits": trap_hits}], indent=0))


def exclude(rid, criterion, reason):
    if criterion not in CRITERIA:
        raise SystemExit(f"criterion must be one of {CRITERIA}")
    rep, cid, k = parse_run_id(rid)
    live = _live_runs()
    if live:
        raise SystemExit(f"live runs present, not unlocking: {live}")
    R.unlock()
    try:
        _check_and_log_trap(f"exclude {rid}")           # a hit aborts here, before any re-arm can erase it
    except BaseException:
        R.lock()
        raise
    try:
        d = ROOT / rid
        if not d.is_dir():
            raise SystemExit(f"{d} not found")
        row = None
        if rid in _verified():
            row = drop_result_row(P8.RESULTS, rid, ROOT / f"results.pre_exclude_{rid}_{int(time.time())}.jsonl")
        rec = {"run_id": rid, "challenge_id": cid, "rep": rep, "attempt": k, "criterion": criterion,
               "detail": reason, "transcript": (row or {}).get("transcript"), "excluded_at": time.time(),
               "excluded_at_iso": _now_iso(), "via": "manual", "had_results_row": row is not None}
        move_to_excluded(d, EXCL, rec, results_row=row)
    finally:
        try:
            _rearm(f"exclude {rid}")
        finally:
            R.lock()
    print(json.dumps(rec))


def report():
    P8.aggregate()
    rows = c0r._read_jsonl(P8.RESULTS)
    excl = _excluded()
    rep = json.loads((ROOT / "report.json").read_text())
    per = {}
    for r in rows:
        per.setdefault(r["subtype"], []).append(r)
    rel = {st: f"{sum(x['bucket'] == 'SOLVED' for x in rr)}/{len(rr)}" for st, rr in sorted(per.items())}
    any_solved = [st for st, rr in per.items() if any(x["bucket"] == "SOLVED" for x in rr)]
    n_prob = len(per)
    non_anchor = {st: rr for st, rr in per.items() if st not in ANCHORS}
    rep["clean_only"] = all(r.get("transcript_clean") for r in rows)
    rep["clean_runs_per_problem"] = {st: len(rr) for st, rr in sorted(per.items())}
    rep["solve_at_1"] = rep["solve_rate_blocked_in_denominator"]["overall"]
    rep["solve_at_3"] = {"problems_solved_at_least_once": len(any_solved), "problems": n_prob,
                         "rate": round(len(any_solved) / n_prob, 3) if n_prob else None,
                         "wilson95": c0r._wilson(len(any_solved), n_prob),
                         "note": "over the clean runs of each problem (normally 3)"}
    rep["reliability_per_problem"] = rel
    rep["reliability_histogram"] = dict(sorted(Counter(rel.values()).items()))
    rep["plaintext_anchors"] = {st: rel.get(st) for st in sorted(ANCHORS)}
    rep["solve_at_1_excluding_anchors"] = c0r._rate([x for rr in non_anchor.values() for x in rr])
    rep["solve_at_3_excluding_anchors"] = {
        "solved": sum(any(x["bucket"] == "SOLVED" for x in rr) for rr in non_anchor.values()),
        "problems": len(non_anchor)}
    rep["by_year_event"] = rep["solve_rate_blocked_in_denominator"]["by_difficulty"]
    rep["headroom"] = {"ceiling": rep["solve_at_1"]["rate"] == 1.0, "floor": rep["solve_at_1"]["rate"] == 0.0}
    rep["retries"] = {r["run_id"]: r["attempt"] for r in rows if r.get("attempt", 1) > 1}
    rep["exclusions"] = {"total": len(excl), "by_criterion": dict(Counter(e["criterion"] for e in excl)),
                         "runs": [{k: e[k] for k in ("run_id", "criterion", "detail")} for e in excl],
                         "rule": "outcome-blind: infra (OPEN + API-error end), transcript_dirty (non-CLI tool "
                                 "use), trap_hit; excluded runs moved to store/p10_c0/_excluded, never aggregated"}
    rep["sample"]["note"] = ("18 holdout problems x 3 independent clean runs; provisional. Contamination: CSAW 2019-2023, "
                             "before the model's training cutoff, public writeups exist -> common constant for all configs")
    rep["sample"]["instances_per_type"] = "1 problem, 3 runs"
    (ROOT / "report.json").write_text(json.dumps(rep, indent=2) + "\n")
    md = P8._md(rep).replace("Phase 8 — Reverse C0 baseline (auto-generated by eval/p8_runner.py)",
                             "Phase 10 — real Reverse (NYU CTF Bench holdout) C0 baseline (auto-generated by eval/p10_runner.py)")
    md = md.replace("| type |", "| problem |").replace("difficulty=", "year=")
    md += "\n## Phase 10 summary (clean runs only)\n\n" + "\n".join(f"- {k}: {json.dumps(rep[k])}" for k in (
        "solve_at_1", "solve_at_3", "reliability_histogram", "reliability_per_problem", "clean_runs_per_problem",
        "plaintext_anchors", "solve_at_1_excluding_anchors", "solve_at_3_excluding_anchors", "headroom",
        "retries")) + "\n"
    md += "\n## Exclusions\n\n" + "\n".join(
        f"- `{e['run_id']}` — {e['criterion']}: {e['detail']}" for e in excl) + "\n"
    (ROOT / "report.md").write_text(md)
    print(md)


def main(argv):
    R.STATIC_SECRETS = P8.STATIC_SECRETS = _secrets()
    cmd = argv[:1]
    if cmd == ["report"]:
        R.unlock()
        try:
            _check_and_log_trap("report")
            try:
                report()
            finally:
                _rearm("report")
        finally:
            R.lock()
        return 0
    if cmd == ["prepare"] and len(argv) == 4 and argv[2] == "--only":
        ids = sorted({re.search(r"rr_[0-9a-f]{6}", x).group(0) for x in argv[3].split(",") if x})
        prepare_only(int(argv[1]), ids)
        return 0
    if cmd == ["verify"] and len(argv) >= 3:
        verify(int(argv[1]), argv[2:])
        return 0
    if cmd == ["exclude"] and len(argv) >= 4:
        exclude(argv[1], argv[2], " ".join(argv[3:]))
        return 0
    return P8.main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
