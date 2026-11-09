"""Phase 46c — first GATE live run (misc). Observation-first, cost-bounded.

Priorities: (1) measure the NOISE FLOOR (identical repeats, how often does solved/failed
flip); (2) observe whether the real-Claude residual judge fires; (3) ONLY if a clean
approach/knowledge AUTO proposal lands on a dev-target, run one noise-aware + holdout gate.

Reuses eval/p45_misc_growth.py for the C1 prompt, signal extraction, lock/trap, verifier,
and the growth Diagnoser. Blind: vault chmod-0 except inside grade(); scorer keys only via
the orchestrator; solvers CLI-only; dev/holdout membership from the flag-free classification.

  python3 eval/p46c_gate.py select
  python3 eval/p46c_gate.py prepare             # noise sessions + prompts + lock + trap
  python3 eval/p46c_gate.py verify              # grade -> runs_46c.json + noise floor
  python3 eval/p46c_gate.py diagnose rules|final
"""
import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
_spec = importlib.util.spec_from_file_location("p45_misc_growth", PROJECT_ROOT / "eval" / "p45_misc_growth.py")
P45 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P45)
R, c0r, verifier, skill_pack = P45.R, P45.c0r, P45.verifier, P45.skill_pack
from growth.diagnoser import Diagnoser, DISPOSITION, is_auto, AUTO_SURFACE, write_requests  # noqa: E402
from growth.loop import RunOutcome  # noqa: E402

ROOT = P45.ROOT                     # store/p45_misc (shared store; distinct run_ids)
ARENA = P45.ARENA
KEYS = P45.KEYS
NOISE_K = 3


def select_sets():
    rows = json.loads(P45.CLASSIFICATION.read_text())["rows"]
    dev = sorted([r for r in rows if r.get("split") == "dev" and r.get("bucket") == "A"], key=lambda r: r["cid"])
    ids = [r["cid"] for r in dev]
    remainder = ids[len(ids) // 2:]          # non-overlap with Phase-45 run #1 (first half)
    dev4 = remainder[:4]
    noise3 = dev4[:3]                          # the K=3 noise-floor problems
    ho = sorted([r["cid"] for r in rows if r.get("split") == "holdout" and r.get("bucket") == "A"])[:4]
    return dev4, noise3, ho


def run_id(cid, k):
    return f"p45ms-{cid}-k{k}"


def _planned():
    """(cid, k, run_id) list: noise3 at K=3, the 4th dev problem once."""
    dev4, noise3, _ = select_sets()
    plan = [(cid, k) for cid in noise3 for k in range(1, NOISE_K + 1)]
    if len(dev4) > 3:
        plan.append((dev4[3], 1))
    return [(cid, k, run_id(cid, k)) for cid, k in plan]


def prepare():
    R.unlock()
    try:
        made = []
        for cid, k, rid in _planned():
            d = ROOT / rid
            if d.exists():
                raise SystemExit(f"{d} exists; refusing to overwrite")
            d.mkdir(parents=True)
            (d / "session.json").write_text(json.dumps({
                "run_id": rid, "challenge_id": cid, "rep": k,
                "challenge_dir": str(ARENA / cid), "status": "OPEN", "exp_count": 0,
                "experiments": [], "started_at": None, "config": "C1",
                "category": "misc_forensics", "prompt_pack": True, "image": P45.IMAGE}, indent=2, sort_keys=True))
            (d / "PROMPT.txt").write_text(P45.c1_prompt(cid, rid))
            made.append(rid)
        n = R.arm_trap()
    finally:
        R.lock()
    dev4, noise3, ho = select_sets()
    print(json.dumps({"prepared": made, "dev4": dev4, "noise3": noise3, "holdout_reg": ho,
                      "K": NOISE_K, "trap_files": n, "locked": R.LOCKFILE.exists()}, indent=1))


def _grade_runs(run_ids):
    """Grade a set of run_ids (blind unlock->verify->re-arm->lock). Returns rows."""
    R.unlock()
    try:
        trap_hits = R.check_trap()
        rows = []
        for cid, k, rid in run_ids:
            d = ROOT / rid
            sess = json.loads((d / "session.json").read_text())
            hdir = d / "harness"
            v = verifier.verify(hdir, cid, scorer_keys_dir=KEYS) if hdir.exists() else {"verdict": "NO_RUN", "solved": False}
            exps = sess.get("experiments", [])
            outcome, kind = c0r._classify(sess, v, exps)
            sig = P45.extract_signals(sess, v["verdict"], P45._transcript_text(d))
            rows.append({"cid": cid, "k": k, "run_id": rid, "verdict": v["verdict"],
                         "solved": bool(v.get("solved")), "outcome": outcome,
                         "failure_kind": kind, "signals": sig})
        R.arm_trap()
    finally:
        R.lock()
    return rows, trap_hits


def _noise_floor(rows):
    byc = defaultdict(list)
    for r in rows:
        byc[r["cid"]].append(bool(r["solved"]))
    per = {}
    flipped = 0
    probed = 0
    for cid, outs in byc.items():
        if len(outs) >= NOISE_K:
            probed += 1
            mixed = len(set(outs)) > 1
            flipped += 1 if mixed else 0
            per[cid] = {"K": len(outs), "solved_count": sum(outs), "outcomes": outs, "flipped": mixed}
        else:
            per[cid] = {"K": len(outs), "solved_count": sum(outs), "outcomes": outs, "flipped": None}
    return {"per_problem": per, "n_probed": probed, "n_flipped": flipped,
            "flip_rate": (flipped / probed) if probed else None}


def verify():
    rows, trap_hits = _grade_runs(_planned())
    (ROOT / "runs_46c.json").write_text(json.dumps(rows, indent=1))
    nf = _noise_floor(rows)
    (ROOT / "noise_floor.json").write_text(json.dumps(nf, indent=1))
    print(json.dumps({"trap_hits": trap_hits, "noise_floor": nf,
                      "rows": [[r["cid"], r["k"], r["solved"], r["failure_kind"]] for r in rows]}, indent=1))


def _runs_as_outcomes():
    return [RunOutcome(cid=r["cid"], outcome=r["outcome"], solved=r["solved"],
                       category="misc", run_dir=str(ROOT / r["run_id"]), signals=r["signals"])
            for r in json.loads((ROOT / "runs_46c.json").read_text())]


def diagnose(mode):
    runs = _runs_as_outcomes()
    failed = [r for r in runs if not r.solved]
    if mode == "rules":
        dx = Diagnoser(judge=None)
        diags = dx.diagnose(failed)
        residual = [{"cid": d["cid"], "excerpt": next((r.signals.get("transcript_excerpt", "")
                                                       for r in failed if r.cid == d["cid"]), "")}
                    for d in diags if d["source"] == "fail-safe" and d["bucket"] == "ambiguous"]
        (ROOT / "diagnoses46c_rules.json").write_text(json.dumps(diags, indent=1))
        (ROOT / "residuals46c_to_judge.json").write_text(json.dumps(residual, indent=1))
        from collections import Counter
        print(json.dumps({"n_failed": len(failed),
                          "bucket_dist": dict(Counter(d["bucket"] for d in diags)),
                          "rule_decided": sum(1 for d in diags if d["source"] == "rule"),
                          "residual_for_claude": [r["cid"] for r in residual]}, indent=1))
        return
    if mode == "final":
        jpath = ROOT / "residual_judgments46c.json"
        judgments = json.loads(jpath.read_text()) if jpath.is_file() else {}
        dx = Diagnoser(judge=None)
        diags = []
        for r in failed:
            base = dx.diagnose_one(r).to_dict()
            if base["source"] == "fail-safe" and r.cid in judgments:
                jj = judgments[r.cid]
                b, conf = jj["bucket"], float(jj.get("confidence", 0.0))
                if b in DISPOSITION and (not is_auto(b) or conf >= 0.66):
                    base.update({"bucket": b, "disposition": DISPOSITION[b], "actionable": is_auto(b),
                                 "confidence": round(conf, 3), "source": "claude-residual",
                                 "reason": jj.get("reason", "")})
            diags.append(base)
        write_requests(diags, ROOT / "requests46c.md")
        (ROOT / "diagnoses46c.json").write_text(json.dumps(diags, indent=1))
        clean = [d for d in diags if d["bucket"] in ("approach", "knowledge_gap") and d["actionable"]]
        print(json.dumps({"diagnoses": [[d["cid"], d["bucket"], d["disposition"], d["source"]] for d in diags],
                          "clean_approach_or_knowledge": [[d["cid"], d["bucket"], AUTO_SURFACE[d["bucket"]]] for d in clean]},
                         indent=1))
        return
    raise SystemExit("mode must be rules|final")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "select":
        d4, n3, ho = select_sets(); print(json.dumps({"dev4": d4, "noise3": n3, "holdout_reg": ho}, indent=1))
    elif cmd == "prepare":
        prepare()
    elif cmd == "verify":
        verify()
    elif cmd == "diagnose":
        diagnose(sys.argv[2] if len(sys.argv) > 2 else "rules")
    else:
        raise SystemExit(__doc__)
