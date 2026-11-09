"""Phase 45 — FIRST real autonomous-growth run (misc, observation-first, 1 cycle).

Scope this invocation (user-approved): DEV BATCH + DIAGNOSE ONLY. Spawn the blind misc
dev-subset agents, grade them (orchestrator unlock->verify->relock), diagnose each failure
with the real Phase-44b Diagnoser (rule table first; the ambiguous residual is judged by
the agent's own Claude judgment, filled into residual_judgments.json), and PROPOSE AUTO
improvements. It STOPS before any holdout re-eval / improver apply / regression gate.

Reuses: eval/c0b_runner.py (lock/atime-trap via P8.R), solver/verifier.py (grading),
eval/c0_runner.py._classify, orchestrator/skill_pack.inject (C1 pack), growth/diagnoser.

Blindness: vault stays chmod-0 except inside verify() (unlock -> grade -> re-arm -> lock);
the solver sub-agents are CLI-only against arena/misc_cli.py; dev/holdout membership comes
from the flag-free store/p18_misc/classification.json, never from a scorer key.

  python3 eval/p45_misc_growth.py select
  python3 eval/p45_misc_growth.py prepare          # sessions + C1 prompts + lock + trap
  python3 eval/p45_misc_growth.py verify           # grade all dev runs -> runs.json
  python3 eval/p45_misc_growth.py diagnose rules    # rule-table pass; dump residuals to judge
  python3 eval/p45_misc_growth.py diagnose final    # apply residual_judgments.json -> diagnoses.json
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
_spec = importlib.util.spec_from_file_location("p8_runner", PROJECT_ROOT / "eval" / "p8_runner.py")
P8 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P8)
R, c0r, verifier = P8.R, P8.c0r, P8.verifier
from orchestrator import skill_pack                       # noqa: E402
from growth.diagnoser import Diagnoser, promotable_successes, DISPOSITION, is_auto, write_requests  # noqa: E402

ROOT = PROJECT_ROOT / "store" / "p45_misc"
ARENA = PROJECT_ROOT / "arena" / "real_misc"
CLASSIFICATION = PROJECT_ROOT / "store" / "p18_misc" / "classification.json"
IMAGE = "ctfagent-misc:0.3"
BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}

# point the shared lock/trap machinery at the p45 store + the misc-real secrets.
ROOT.mkdir(parents=True, exist_ok=True)
R.ROOT, R.RESULTS = ROOT, ROOT / "results.jsonl"
R.LOCKFILE, R.TRAPFILE = ROOT / "lock.json", ROOT / "trap.json"
R.STATIC_SECRETS = ["vault", "eval/scorer_keys", "eval/packs", "eval/make_dev_set.py",
                    "eval/make_dev_challenge.py", "store/c0", "store/runs", "store/c0b",
                    "store/c0b2", "store/p6_c0", "store/p6_c1", "store/p8_c0", "store/p10_c0",
                    "store/p14_c0", "store/p16a_c0", "store/p22_misc"]
KEYS = R.VAULT / "scorer_keys_misc_real"


# ---- deterministic, blind-safe set selection -------------------------------
def select_sets():
    rows = json.loads(CLASSIFICATION.read_text())["rows"]
    dev = sorted([r for r in rows if r.get("split") == "dev" and r.get("bucket") == "A"],
                 key=lambda r: r["cid"])
    ho = sorted([r for r in rows if r.get("split") == "holdout" and r.get("bucket") == "A"],
                key=lambda r: r["cid"])
    dev_ids = [r["cid"] for r in dev]
    dev_subset = dev_ids[:len(dev_ids) // 2]              # first half, sorted
    holdout_reg = [r["cid"] for r in ho][:4]             # fixed small regression set
    meta = {r["cid"]: r for r in rows}
    return dev_subset, holdout_reg, meta


def run_id_for(cid):
    return f"p45ms-{cid}"


# ---- the C1 blind-solver prompt (base + injected misc pack) -----------------
def base_prompt(cid, run_id):
    return (
        f"You are solving ONE blind CTF challenge (category: misc/forensics), id {cid}.\n"
        f"You have NO access to the flag or any answer key. Work ONLY through this CLI, one\n"
        f"line per shell call, nothing else:\n"
        f"  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py {run_id} info\n"
        f"  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py {run_id} exp <name>   < code.py  (python3 -I in a --network none container)\n"
        f"  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py {run_id} report <FLAG> <exp_id>\n"
        f"  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py {run_id} give_up <analysis|impl|tool> <reason>\n"
        f"  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py {run_id} status\n"
        f"Rules: inspect the files FIRST (file/exiftool/strings/binwalk) before writing a full\n"
        f"extractor; e01 can NEVER be the cited evidence. Do NOT read any file under vault/,\n"
        f"eval/scorer_keys/, or other runs' store dirs; do NOT use shell pipes/redirects/`$()`\n"
        f"— only the exact CLI lines above. Budget: {BUDGET['max_experiments']} experiments / "
        f"{BUDGET['wall_s']}s. Finish with `report <FLAG> <exp_id>` citing the experiment whose\n"
        f"stdout PRINTED the flag, or `give_up` cleanly. NEVER report a guessed/pattern-matched\n"
        f"flag — only one an in-container experiment actually produced.")


def c1_prompt(cid, run_id):
    return skill_pack.inject(base_prompt(cid, run_id), "misc", full=True)


# ---- prepare: sessions + prompts + lock + trap -----------------------------
def prepare():
    dev, ho, meta = select_sets()
    R.unlock()
    try:
        made = []
        for cid in dev:
            rid = run_id_for(cid)
            d = ROOT / rid
            if d.exists():
                raise SystemExit(f"{d} exists; refusing to overwrite")
            d.mkdir(parents=True)
            (d / "session.json").write_text(json.dumps({
                "run_id": rid, "challenge_id": cid, "rep": 1,
                "challenge_dir": str(ARENA / cid), "status": "OPEN", "exp_count": 0,
                "experiments": [], "started_at": None,
                "config": "C1", "category": "misc_forensics", "prompt_pack": True,
                "image": IMAGE, "boundary": "plain container, --network none"}, indent=2, sort_keys=True))
            (d / "PROMPT.txt").write_text(c1_prompt(cid, rid))
            made.append(rid)
        (ROOT / "sets.json").write_text(json.dumps(
            {"dev_subset": dev, "holdout_reg": ho,
             "note": "holdout_reg is NOT run in this dev+diagnose-only invocation"}, indent=1))
        n = R.arm_trap()
    finally:
        R.lock()
    print(json.dumps({"prepared": made, "dev_subset": dev, "holdout_reg": ho,
                      "trap_files": n, "locked": R.LOCKFILE.exists()}, indent=1))


# ---- signal extraction from the agent's OWN trace (no key reads) -----------
_CYBER = re.compile(r"\[cyber\]|weaponiz|i can't help|i cannot help|i'm unable to help", re.I)
_TOOLMISS = re.compile(r"command not found|not found|No such file.*(sqlmap|vol|john|zbar|ffuf|binwalk)"
                       r"|is not installed", re.I)
_HARNESS = re.compile(r"Traceback|PermissionError|docker:|Cannot connect to the Docker|OSError|"
                      r"deploy\.json|boundary_init", re.I)


def extract_signals(sess, verdict, transcript_text):
    exps = sess.get("experiments", [])
    n_ok = sum(1 for e in exps if e.get("status") == "ok")
    gu = (sess.get("give_up") or {}).get("kind", "")
    status = sess.get("status", "")
    # stalled discriminators (Phase 46b): did the run keep LOOPING without progress?
    n_err = sum(1 for e in exps if e.get("status") in ("error", "timeout"))
    repeated_error_class = n_err >= 2
    stalled = (gu == "impl") or repeated_error_class
    sig = {
        "give_up_kind": gu,
        "n_exp": len(exps),
        "n_exp_ok": n_ok,
        "n_exp_err": n_err,
        "repeated_error_class": repeated_error_class,
        "stalled": stalled,
        "budget_exhausted": status == "BUDGET_EXHAUSTED" or sess.get("exp_count", 0) >= BUDGET["max_experiments"],
        "fws": verdict == verifier.FLAG_WITHOUT_SOLUTION,
        "cyber_blocked": bool(_CYBER.search(transcript_text)),
        "tool_missing": gu == "tool" or bool(_TOOLMISS.search(transcript_text)),
        "harness_error": (n_ok == 0 and len(exps) > 0 and bool(_HARNESS.search(transcript_text))),
        "transcript_excerpt": transcript_text[-1500:],
    }
    return sig


# ---- verify: grade every dev run (blind unlock->grade->re-arm->lock) --------
def _transcript_text(d):
    # the agent's own CLI call log + stdout, as the harness recorded it (no key reads).
    parts = []
    for name in ("c0_calls.jsonl", "harness/commands.jsonl"):
        p = d / name
        if p.is_file():
            parts.append(p.read_text(errors="replace"))
    return "\n".join(parts)


def verify():
    dev, ho, meta = select_sets()
    R.unlock()
    try:
        trap_hits = R.check_trap()
        out = []
        for cid in dev:
            rid = run_id_for(cid)
            d = ROOT / rid
            sess = json.loads((d / "session.json").read_text())
            hdir = d / "harness"
            v = verifier.verify(hdir, cid, scorer_keys_dir=KEYS) if hdir.exists() else {"verdict": "NO_RUN", "solved": False}
            exps = sess.get("experiments", [])
            outcome, kind = c0r._classify(sess, v, exps)
            sig = extract_signals(sess, v["verdict"], _transcript_text(d))
            out.append({"cid": cid, "run_id": rid, "verdict": v["verdict"],
                        "solved": bool(v.get("solved")), "outcome": outcome,
                        "failure_kind": kind, "signals": sig,
                        "subtype": meta[cid].get("nyu_id"), "category": meta[cid].get("category")})
        R.arm_trap()        # re-arm AFTER the verifier's key reads
    finally:
        R.lock()
    (ROOT / "runs.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({"trap_hits": trap_hits,
                      "runs": [[r["cid"], r["outcome"], r["solved"], r["failure_kind"]] for r in out]},
                     indent=1))


# ---- diagnose: rule table, then the real-Claude residual judgment ----------
def _runs():
    from growth.loop import RunOutcome
    return [RunOutcome(cid=r["cid"], outcome=r["outcome"], solved=r["solved"],
                       category=r.get("category", ""), run_dir=str(ROOT / r["run_id"]),
                       signals=r["signals"]) for r in json.loads((ROOT / "runs.json").read_text())]


def diagnose(mode):
    runs = _runs()
    failed = [r for r in runs if not r.solved]
    if mode == "rules":
        dx = Diagnoser(judge=None)                    # residual -> ambiguous (fail-safe) for now
        diags = dx.diagnose(failed)
        residual = [{"cid": d["cid"], "excerpt": next((r.signals.get("transcript_excerpt", "")
                                                       for r in failed if r.cid == d["cid"]), "")}
                    for d in diags if d["source"] == "fail-safe" and d["bucket"] == "ambiguous"]
        (ROOT / "diagnoses_rules.json").write_text(json.dumps(diags, indent=1))
        (ROOT / "residuals_to_judge.json").write_text(json.dumps(residual, indent=1))
        print(json.dumps({"n_failed": len(failed),
                          "rule_decided": [d["cid"] for d in diags if d["source"] == "rule"],
                          "residual_for_claude": [r["cid"] for r in residual]}, indent=1))
        return
    if mode == "final":
        jpath = ROOT / "residual_judgments.json"
        judgments = json.loads(jpath.read_text()) if jpath.is_file() else {}
        # the residual judge = the agent's own Claude verdict, recorded per cid as
        # {"bucket": <bucket>, "confidence": <float>}; fail-safe asymmetry still applies.
        def judge(signals, excerpt, _j=judgments):
            cid = next((c for c, _ in _j.items() if _j[c].get("_excerpt_tag") == signals.get("_tag")), None)
            return (None, 0.0)   # placeholder; final pass uses per-cid override below
        dx = Diagnoser(judge=None)
        diags = []
        for r in failed:
            base = dx.diagnose_one(r).to_dict()
            if base["source"] == "fail-safe" and r.cid in judgments:
                jj = judgments[r.cid]
                b, conf = jj["bucket"], float(jj.get("confidence", 0.0))
                if b in DISPOSITION and (not is_auto(b) or conf >= 0.66):
                    base.update({"bucket": b, "disposition": DISPOSITION[b],
                                 "actionable": is_auto(b), "confidence": round(conf, 3),
                                 "source": "claude-residual", "reason": jj.get("reason", "")})
                # else: keep ambiguous (fail-safe) — a low-confidence AUTO verdict is refused
            diags.append(base)
        write_requests(diags, ROOT / "requests.md")
        (ROOT / "diagnoses.json").write_text(json.dumps(diags, indent=1))
        promotable = [r.cid for r in promotable_successes(runs)]
        print(json.dumps({"diagnoses": [[d["cid"], d["bucket"], d["disposition"], d["source"]] for d in diags],
                          "promotable_successes": promotable}, indent=1))
        return
    raise SystemExit("diagnose mode must be 'rules' or 'final'")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "select":
        dev, ho, meta = select_sets()
        print(json.dumps({"dev_subset": dev, "holdout_reg": ho}, indent=1))
    elif cmd == "prepare":
        prepare()
    elif cmd == "verify":
        verify()
    elif cmd == "diagnose":
        diagnose(sys.argv[2] if len(sys.argv) > 2 else "rules")
    else:
        raise SystemExit(__doc__)
