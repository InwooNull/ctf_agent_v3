"""Phase 51 — autonomous growth, ONE full cycle over the entire misc dev batch (0.5).

Scope (user-approved "Cycle 1 + checkpoint"): run the WHOLE blind dev batch at K=1 on
ctfagent-misc:0.5, grade it, diagnose every failure with the real Phase-44b/46b Diagnoser,
and PROMOTE every verified (non-FWS) success into the experience store (always — storage
of verified data is unconditional). The aggregate "total solved count" for the cycle is
the headline metric. Gated experience INJECTION and AUTO-lever gating run after this, as
separate steps (holdout-gated), then we checkpoint and report.

Dev batch = all 12 dev-A misc/forensics (store/p18_misc/classification.json) MINUS the
non-blind mr_de0abb = 11 blind challenges. Image 0.5, budget 12 exp / 1200 s / 90 s-exp.
Isolated from the p45/p48/p50 artifacts: fresh store root store/p51_misc + run-id prefix
p51c1- + its own container-name namespace (46a/50a isolation).

Reuses: eval/p8_runner.py (R: lock / atime-trap), solver/verifier.py (grading),
eval/c0_runner.py._classify, orchestrator/skill_pack.inject (C1 pack), growth.diagnoser,
growth.experience.

  python3 eval/p51_cycle.py select
  python3 eval/p51_cycle.py prepare        # 11 sessions + C1 prompts + lock + trap
  python3 eval/p51_cycle.py verify         # grade all dev runs -> runs.json
  python3 eval/p51_cycle.py diagnose rules # rule-table pass; dump residuals to judge
  python3 eval/p51_cycle.py diagnose final # apply residual_judgments.json -> diagnoses.json
  python3 eval/p51_cycle.py promote        # verified successes -> store/experience_misc.jsonl
  python3 eval/p51_cycle.py report         # aggregate cycle report
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
from orchestrator import skill_pack                                        # noqa: E402
from growth.diagnoser import (Diagnoser, promotable_successes, DISPOSITION,  # noqa: E402
                              is_auto, write_requests)
from growth import experience as X                                        # noqa: E402

ROOT = PROJECT_ROOT / "store" / "p51_misc"
ARENA = PROJECT_ROOT / "arena" / "real_misc"
CLASSIFICATION = PROJECT_ROOT / "store" / "p18_misc" / "classification.json"
IMAGE = "ctfagent-misc:0.5"
BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
NON_BLIND = {"mr_de0abb"}                 # flag/answer exposure established in prior phases -> excluded

ROOT.mkdir(parents=True, exist_ok=True)
R.ROOT, R.RESULTS = ROOT, ROOT / "results.jsonl"
R.LOCKFILE, R.TRAPFILE = ROOT / "lock.json", ROOT / "trap.json"
R.STATIC_SECRETS = ["vault", "eval/scorer_keys", "eval/packs", "eval/make_dev_set.py",
                    "eval/make_dev_challenge.py", "store/c0", "store/runs", "store/c0b",
                    "store/c0b2", "store/p6_c0", "store/p6_c1", "store/p8_c0", "store/p10_c0",
                    "store/p14_c0", "store/p16a_c0", "store/p22_misc"]
KEYS = R.VAULT / "scorer_keys_misc_real"


def select_sets():
    rows = json.loads(CLASSIFICATION.read_text())["rows"]
    dev = sorted([r for r in rows if r.get("split") == "dev" and r.get("bucket") == "A"
                  and r["cid"] not in NON_BLIND], key=lambda r: r["cid"])
    ho = sorted([r for r in rows if r.get("split") == "holdout" and r.get("bucket") == "A"],
                key=lambda r: r["cid"])
    dev_ids = [r["cid"] for r in dev]
    holdout_reg = [r["cid"] for r in ho][:4]
    meta = {r["cid"]: r for r in rows}
    return dev_ids, holdout_reg, meta


def run_id_for(cid):
    return f"p51c1-{cid}"


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


def prepare():
    dev, ho, meta = select_sets()
    R.unlock()
    try:
        made, skipped = [], []
        for cid in dev:
            rid = run_id_for(cid)
            d = ROOT / rid
            if d.exists():
                skipped.append(rid)
                continue
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
            {"dev_batch": dev, "holdout_reg": ho, "n_dev": len(dev),
             "excluded_non_blind": sorted(NON_BLIND), "image": IMAGE, "budget": BUDGET}, indent=1))
        n = R.arm_trap()
    finally:
        R.lock()
    guard = R.guard_prespawn(dev, ROOT)                 # STANDARD pre-spawn blind guard
    print(json.dumps({"prepared": made, "skipped_existing": skipped, "n_dev": len(dev),
                      "holdout_reg": ho, "trap_files": n, "locked": R.LOCKFILE.exists(),
                      "prespawn_guard": guard}, indent=1))


_CYBER = re.compile(r"\[cyber\]|weaponiz|i can't help|i cannot help|i'm unable to help", re.I)
_TOOLMISS = re.compile(r"command not found|not found|No such file.*(sqlmap|vol|john|zbar|ffuf|binwalk|tesseract|cv2)"
                       r"|is not installed|ModuleNotFoundError", re.I)
_HARNESS = re.compile(r"Traceback|PermissionError|docker:|Cannot connect to the Docker|OSError|"
                      r"deploy\.json|boundary_init", re.I)


def extract_signals(sess, verdict, transcript_text):
    exps = sess.get("experiments", [])
    n_ok = sum(1 for e in exps if e.get("status") == "ok")
    gu = (sess.get("give_up") or {}).get("kind", "")
    status = sess.get("status", "")
    n_err = sum(1 for e in exps if e.get("status") in ("error", "timeout"))
    repeated_error_class = n_err >= 2
    stalled = (gu == "impl") or repeated_error_class
    reported = sess.get("reported") or {}
    winning_exp = (reported.get("evidence_refs") or [""])[0]       # exp id ONLY, never the flag value
    return {
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
        "winning_exp": winning_exp,
        "transcript_excerpt": transcript_text[-1500:],
    }


def _transcript_text(d):
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
            if not d.exists():
                out.append({"cid": cid, "run_id": rid, "verdict": "NO_RUN", "solved": False,
                            "outcome": "NO_RUN", "failure_kind": "no_run", "signals": {},
                            "subtype": meta[cid].get("nyu_id"), "category": meta[cid].get("category")})
                continue
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
        R.arm_trap()
    finally:
        R.lock()
    (ROOT / "runs.json").write_text(json.dumps(out, indent=1))
    solved = [r["cid"] for r in out if r["solved"]]
    print(json.dumps({"trap_hits": trap_hits, "total_solved": len(solved), "n_dev": len(out),
                      "solved": solved,
                      "runs": [[r["cid"], r["outcome"], r["solved"], r["failure_kind"]] for r in out]},
                     indent=1))


def _runs():
    from growth.loop import RunOutcome
    out = []
    for r in json.loads((ROOT / "runs.json").read_text()):
        ro = RunOutcome(cid=r["cid"], outcome=r["outcome"], solved=r["solved"],
                        category=r.get("category", "") or "", run_dir=str(ROOT / r["run_id"]),
                        signals=r["signals"])
        ro.subtype = r.get("subtype")
        ro.winning_exp = (r.get("signals") or {}).get("winning_exp", "")
        out.append(ro)
    return out


def diagnose(mode):
    runs = _runs()
    failed = [r for r in runs if not r.solved]
    if mode == "rules":
        dx = Diagnoser(judge=None)
        diags = dx.diagnose(failed)
        residual = [{"cid": d["cid"], "excerpt": next((r.signals.get("transcript_excerpt", "")
                                                       for r in failed if r.cid == d["cid"]), "")}
                    for d in diags if d["source"] == "fail-safe" and d["bucket"] == "ambiguous"]
        (ROOT / "diagnoses_rules.json").write_text(json.dumps(diags, indent=1))
        (ROOT / "residuals_to_judge.json").write_text(json.dumps(residual, indent=1))
        print(json.dumps({"n_failed": len(failed),
                          "rule_decided": [[d["cid"], d["bucket"]] for d in diags if d["source"] == "rule"],
                          "residual_for_claude": [r["cid"] for r in residual]}, indent=1))
        return
    if mode == "final":
        jpath = ROOT / "residual_judgments.json"
        judgments = json.loads(jpath.read_text()) if jpath.is_file() else {}
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
            diags.append(base)
        write_requests(diags, ROOT / "requests.md")
        (ROOT / "diagnoses.json").write_text(json.dumps(diags, indent=1))
        promotable = [r.cid for r in promotable_successes(runs)]
        # rank AUTO failures by margin (closest to the finish line first) for the gate.
        auto = [d for d in diags if d["disposition"] == "AUTO"]
        def margin(d):
            r = next((x for x in failed if x.cid == d["cid"]), None)
            s = r.signals if r else {}
            return (s.get("n_exp_ok", 0), s.get("n_exp", 0))      # more successful exps = later stage reached
        auto_ranked = [d["cid"] for d in sorted(auto, key=margin, reverse=True)]
        (ROOT / "auto_gate_candidates.json").write_text(json.dumps(auto_ranked, indent=1))
        print(json.dumps({"diagnoses": [[d["cid"], d["bucket"], d["disposition"], d["source"]] for d in diags],
                          "promotable_successes": promotable,
                          "auto_gate_ranked": auto_ranked}, indent=1))
        return
    raise SystemExit("diagnose mode must be 'rules' or 'final'")


def repair():
    """Fix the chain-corrupted vault lock/trap, then arm the trap over the FULL secret
    tree and re-lock cleanly under p51. Restores each secret path to its true mode
    (dirs 0755 / files 0644), clears any stale lock holders, arms the atime trap, locks.

    This WEAKENS then re-strengthens the vault (chmod 0755 -> arm -> chmod 0), so the
    auto-mode safety classifier denies it when the orchestrator runs it as a tool call.
    Run it yourself via the `!` prefix so it executes with your authority:
        ! python3 eval/p51_cycle.py repair
    End state: vault + all secrets chmod-0 (blind), trap armed over the full tree, and
    store/p51_misc/lock.json recording the TRUE modes so a later `verify` self-heals."""
    import os, stat
    for rel in R.STATIC_SECRETS:
        p = PROJECT_ROOT / rel
        if p.exists():
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
    for lf in (PROJECT_ROOT / "store" / "p45_misc" / "lock.json", R.LOCKFILE):
        if lf.exists():
            lf.unlink()
    n = R.arm_trap()                      # full-tree arm while readable
    R.lock()                              # records true modes, chmods secrets -> 0
    print(json.dumps({"trap_files": n, "locked": R.LOCKFILE.exists(),
                      "vault_mode": oct(stat.S_IMODE((PROJECT_ROOT / 'vault').stat().st_mode))}, indent=1))


def promote():
    """Promote every verified (non-FWS) success to store/experience_misc.jsonl. Always
    stores (verified data); draws only from promotable_successes (FWS excluded). Optional
    per-cid one-line recipe override from ROOT/promote_notes.json {cid: recipe}."""
    runs = _runs()
    successes = promotable_successes(runs)
    notes_path = ROOT / "promote_notes.json"
    notes = json.loads(notes_path.read_text()) if notes_path.is_file() else {}
    recs = []
    for r in successes:
        d = ROOT / run_id_for(r.cid)
        recs.append(X.build_record(r, transcript_text=_transcript_text(d),
                                   recipe=notes.get(r.cid)))
    written = X.promote(recs, store_path=X.DEFAULT_STORE)
    (ROOT / "promotion.json").write_text(json.dumps(
        {"promotable_cids": [r.cid for r in successes],
         "newly_promoted": [{"subtype": w["subtype"], "technique": w["technique"],
                             "source": w["source"]} for w in written],
         "store": str(X.DEFAULT_STORE)}, indent=1))
    print(json.dumps({"n_promotable": len(successes), "n_newly_promoted": len(written),
                      "store_total": len(X.load())}, indent=1))


def report():
    runs = json.loads((ROOT / "runs.json").read_text())
    diags = json.loads((ROOT / "diagnoses.json").read_text()) if (ROOT / "diagnoses.json").is_file() else []
    solved = [r["cid"] for r in runs if r["solved"]]
    failed = [r["cid"] for r in runs if not r["solved"]]
    by_bucket = {}
    for d in diags:
        by_bucket.setdefault(d["bucket"], []).append(d["cid"])
    out = {
        "phase": "51 cycle 1 (misc 0.5, full blind dev batch, K=1)",
        "image": IMAGE, "budget": BUDGET,
        "n_dev": len(runs), "total_solved": len(solved), "total_failed": len(failed),
        "solved": sorted(solved), "failed": sorted(failed),
        "by_cat": {
            "forensics": {"n": sum(1 for r in runs if r.get("category") == "forensics"),
                          "solved": sum(1 for r in runs if r.get("category") == "forensics" and r["solved"])},
            "misc": {"n": sum(1 for r in runs if r.get("category") == "misc"),
                     "solved": sum(1 for r in runs if r.get("category") == "misc" and r["solved"])},
        },
        "diagnosis_distribution": {b: sorted(c) for b, c in sorted(by_bucket.items())},
        "fws": [d["cid"] for d in diags if d.get("fws")],
    }
    (ROOT / "cycle1_report.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "select":
        dev, ho, meta = select_sets()
        print(json.dumps({"dev_batch": dev, "n_dev": len(dev), "holdout_reg": ho}, indent=1))
    elif cmd == "prepare":
        prepare()
    elif cmd == "guard":
        dev, _, _ = select_sets()
        print(json.dumps(R.guard_prespawn(dev, ROOT), indent=1))
    elif cmd == "unguard":
        print(json.dumps(R.unguard_prespawn(ROOT), indent=1))
    elif cmd == "verify":
        verify()
    elif cmd == "diagnose":
        diagnose(sys.argv[2] if len(sys.argv) > 2 else "rules")
    elif cmd == "repair":
        repair()
    elif cmd == "promote":
        promote()
    elif cmd == "report":
        report()
    else:
        raise SystemExit(__doc__)
