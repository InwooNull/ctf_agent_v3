"""C0 agent CLI — the only interface a C0 (single ReAct loop) solver session uses.

Every call is a fresh process; the run's state lives on disk under
store/c0/<run_id>/ and is restored into a CryptoHarness on each call. All solve
code goes through CryptoHarness.run_experiment (container, --network none).
This module never reads eval/scorer_keys; verdicts come later from the runner.

Usage (cwd = ~/ctf_agent_v3):
  python3 eval/c0_cli.py <run_id> info
  python3 eval/c0_cli.py <run_id> exp <name>  < code.py      # code on stdin
  python3 eval/c0_cli.py <run_id> report <FLAG> <exp_id> [<exp_id> ...]
  python3 eval/c0_cli.py <run_id> give_up <tool|analysis> <reason...>
  python3 eval/c0_cli.py <run_id> status

Budget (enforced here, identical for every run): C0_BUDGET below. Every `exp`
call counts, including errors and dedup hits. `report` and `give_up` are
terminal: the session is closed and further calls are refused.
"""
import json
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from solver.crypto_harness import CryptoHarness  # noqa: E402

C0_ROOT = PROJECT_ROOT / "store" / "c0"
C0_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 30}
OUTPUT_SHOW = 6000          # chars of stdout/stderr shown back to the agent
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")


class CliError(Exception):
    pass


def _session_path(run_id):
    return C0_ROOT / run_id / "session.json"


def load_session(run_id):
    p = _session_path(run_id)
    if not p.exists():
        raise CliError(f"unknown run_id {run_id!r}")
    return json.loads(p.read_text())


def save_session(run_id, sess):
    p = _session_path(run_id)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(sess, indent=2, sort_keys=True))
    tmp.replace(p)


def _log_call(run_id, rec):
    rec = dict(rec, t=time.time())
    with open(C0_ROOT / run_id / "c0_calls.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def open_harness(run_id, sess):
    """Reconstruct the harness for this run, restoring persisted state."""
    run_dir = C0_ROOT / run_id / "harness"
    prev = None
    if (run_dir / "state.json").exists():
        prev = json.loads((run_dir / "state.json").read_text())
    h = CryptoHarness("harness", sess["challenge_dir"], store_root=C0_ROOT / run_id,
                      budget={"time_s": C0_BUDGET["wall_s"],
                              "max_attempts": C0_BUDGET["max_experiments"]})
    # harness files live at store/c0/<run_id>/harness/
    if prev:
        h.budget_spent = prev["budget_spent"]
        h.hypotheses = prev["hypotheses"]
        h.candidates = prev["candidates"]
        h.experiments = prev["experiments"]
        for rec in h.experiments.values():
            if rec.get("execution_status") == "ok" and not rec.get("cached") and rec.get("dedup_key"):
                h._ref_by_key[rec["dedup_key"]] = {
                    "exp_id": rec["exp_id"], "stdout_ref": rec["stdout_ref"],
                    "status": rec["execution_status"], "profile": rec["sandbox_profile"]}
        h._save()
    return h


def _remaining(sess):
    used = sess["exp_count"]
    elapsed = time.time() - sess["started_at"] if sess.get("started_at") else 0.0
    return {"experiments_left": C0_BUDGET["max_experiments"] - used,
            "wall_s_left": round(C0_BUDGET["wall_s"] - elapsed, 1)}


def _budget_ok(sess):
    r = _remaining(sess)
    if r["experiments_left"] <= 0:
        return False, "max_experiments"
    if r["wall_s_left"] <= 0:
        return False, "wall_s"
    return True, None


def _clip(s):
    if len(s) <= OUTPUT_SHOW:
        return s
    return s[:OUTPUT_SHOW] + f"\n...[truncated, {len(s) - OUTPUT_SHOW} more chars]"


def cmd_info(run_id, sess, args):
    ch = json.loads((Path(sess["challenge_dir"]) / "challenge.json").read_text())
    files = []
    for f in ch.get("files", []):
        files.append({"name": f, "size": (Path(sess["challenge_dir"]) / f).stat().st_size,
                      "container_path": f"/input/{f}"})
    out = {"title": ch["title"], "category": ch["category"], "difficulty": ch.get("difficulty"),
           "description": ch["description"], "files": files,
           "budget": C0_BUDGET, "remaining": _remaining(sess),
           "how": "files are only readable inside experiments, at /input/<name> (read-only). "
                  "Run code with `exp`. Writable cwd inside the container is /work."}
    print(json.dumps(out, indent=2))


def cmd_exp(run_id, sess, args):
    if len(args) != 1:
        raise CliError("usage: exp <name>   (python code on stdin)")
    name = args[0]
    if not NAME_RE.match(name):
        raise CliError("name must match [A-Za-z][A-Za-z0-9_]{0,31}")
    code = sys.stdin.read()
    if not code.strip():
        raise CliError("empty code on stdin")
    ok, why = _budget_ok(sess)
    if not ok:
        sess["status"] = "BUDGET_EXHAUSTED"
        sess["closed_by"] = why
        save_session(run_id, sess)
        raise CliError(f"budget exhausted ({why}); session closed. You may only stop now.")
    sess["exp_count"] += 1
    full = f"e{sess['exp_count']:02d}_{name}"        # unique per call: names never collide
    save_session(run_id, sess)
    h = open_harness(run_id, sess)
    o = h.run_experiment({"name": full, "code": code, "timeout": C0_BUDGET["exp_timeout_s"]})
    stderr = h._read_ref(f"{o.exp_id}.stderr")
    sess["experiments"].append({"exp_id": o.exp_id, "status": o.execution_status,
                                "cached": o.cached, "profile": o.sandbox_profile})
    save_session(run_id, sess)
    print(f"exp_id: {o.exp_id}")
    print(f"status: {o.execution_status}  profile: {o.sandbox_profile}  cached: {o.cached}")
    print("--- stdout ---")
    print(_clip(o.stdout))
    if stderr.strip():
        print("--- stderr ---")
        print(_clip(stderr))
    print(f"--- remaining: {json.dumps(_remaining(sess))}")
    return o.execution_status


def cmd_report(run_id, sess, args):
    if len(args) < 2:
        raise CliError("usage: report <FLAG> <exp_id> [<exp_id> ...]")
    flag = args[0]
    prefix = sess["challenge_id"] + "-"
    refs = [r if r.startswith(prefix) else prefix + r for r in args[1:]]   # allow short ids
    known = {e["exp_id"] for e in sess["experiments"]}
    bad = [r for r in refs if r not in known]
    if bad:
        raise CliError(f"unknown exp_id(s) {bad}; evidence must be experiments of this run")
    h = open_harness(run_id, sess)
    h.report_candidate(flag, refs)
    sess["status"] = "REPORTED"
    sess["reported"] = {"value": flag, "evidence_refs": refs}
    sess["ended_at"] = time.time()
    save_session(run_id, sess)
    print("candidate recorded; session closed.")


def cmd_give_up(run_id, sess, args):
    if len(args) < 2 or args[0] not in ("tool", "analysis"):
        raise CliError("usage: give_up <tool|analysis> <reason...>")
    sess["status"] = "GIVE_UP"
    sess["give_up"] = {"kind": args[0], "reason": " ".join(args[1:])}
    sess["ended_at"] = time.time()
    save_session(run_id, sess)
    print("give-up recorded; session closed.")


def cmd_status(run_id, sess, args):
    print(json.dumps({"status": sess["status"], "remaining": _remaining(sess),
                      "experiments": sess["experiments"]}, indent=2))


COMMANDS = {"info": cmd_info, "exp": cmd_exp, "report": cmd_report,
            "give_up": cmd_give_up, "status": cmd_status}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 2
    run_id, cmd, args = argv[0], argv[1], argv[2:]
    try:
        sess = load_session(run_id)
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if sess["status"] != "OPEN" and cmd != "status":
        _log_call(run_id, {"cmd": cmd, "ok": False, "error": "session closed"})
        print(f"error: session is closed ({sess['status']})", file=sys.stderr)
        return 3
    if not sess.get("started_at") and cmd != "status":
        sess["started_at"] = time.time()        # wall clock starts at the agent's first call
        save_session(run_id, sess)
    try:
        res = COMMANDS[cmd](run_id, sess, args)
    except CliError as e:
        _log_call(run_id, {"cmd": cmd, "ok": False, "error": str(e)})
        print(f"error: {e}", file=sys.stderr)
        return 2
    _log_call(run_id, {"cmd": cmd, "ok": True, "result": res})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
