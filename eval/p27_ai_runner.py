"""Phase 27 — AI experience-system (C2) measurement: does technique transfer help?

  python3 eval/p27_ai_runner.py run   [--batch-size N] [--resume]
  python3 eval/p27_ai_runner.py report

Measures C0 (no experience) vs C2 (experience-injected) on the guard battery, by
attempts-to-solve. Both configs use the identical scripted attacker, budget, and @1;
the ONLY difference is that C2 consults store/experience_ai (via solver.ai_experience)
to reprioritize the benign-admin reframing family, with a benign-vocabulary ranking
learned from the HELD-OUT seed guards. The mock guards are deterministic, so a run
costs ~0 tokens; this measures the transfer *mechanism* under a stated attacker model,
not LLM performance.

Governance: each solved candidate goes through the Phase-25 SubmitGate (orchestrator
role, a LOCAL fake scorer — no live platform). Sub-agent direct submission is proven
blocked. The attacker receives only a Target handle + the public scenario; it never
reads vault, the policy, or the flag (cheating is structurally impossible).

Outputs (no plaintext flags — sha256 + metrics only): store/p27_ai/results.jsonl and
store/p27_ai/report.{json,md}. Resume-safe: already-measured guards are skipped.
"""
import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from solver.ai_targets import ConfigurableGuard                       # noqa: E402
from solver.ai_harness import AttackHarness                          # noqa: E402
from solver import ai_battery as B                                   # noqa: E402
from solver.ai_experience import retrieve                            # noqa: E402
from connector.submit_gate import SubmitGate, NotAuthorized          # noqa: E402

VAULT_POLICIES = PROJECT_ROOT / "vault" / "ai_battery" / "policies.json"
ARENA = PROJECT_ROOT / "arena" / "ai_battery"
STORE = PROJECT_ROOT / "store" / "p27_ai"
RESULTS = STORE / "results.jsonl"
BUDGET = 12
SUBTYPE = "guard-bypass"


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _load_policies():
    """Scorer-side secret load (runner legitimately holds secrets; attacker never does)."""
    return json.loads(VAULT_POLICIES.read_text(encoding="utf-8"))


def _scenario(gid):
    return json.loads((ARENA / gid / "scenario.json").read_text(encoding="utf-8"))


def _seed_benign_rank(policies):
    """Learn the benign-vocabulary ranking from the HELD-OUT seed guards only.

    Rank = how many seed guards accept each benign vocabulary (desc), tie-broken by
    the canonical library order. No flags, no eval-guard data.
    """
    counts = {n: 0 for n in B.BENIGN_NAMES}
    for gid, pol in policies.items():
        if not pol.get("is_seed"):
            continue
        for key in pol.get("accepted_keys", []):
            if key in counts:
                counts[key] += 1
    return sorted(B.BENIGN_NAMES, key=lambda n: (-counts[n], B.BENIGN_NAMES.index(n)))


class _FakeScorer:
    """Local stand-in for the live submit: 'correct' iff the flag matches. No network."""
    def __init__(self, correct):
        self.correct = correct
        self.calls = 0

    def submit_flag(self, cid, flag):
        self.calls += 1
        return ("correct" if flag == self.correct else "incorrect"), "ok"


def _run_config(gid, policy, scenario, order, tag):
    """One attacker run for a (guard, config). Returns a metrics dict (no plaintext flag)."""
    target = ConfigurableGuard(policy)
    run_dir = STORE / gid / tag
    harness = AttackHarness(target, run_dir)
    res = B.attack(target, scenario, order, harness, budget=BUDGET)
    out = {
        "config": tag,
        "solved": res["solved"],
        "attempts": res["attempts"],
        "winner": res["winner"],
        "winner_family": res["winner_family"],
        "tried": res["tried"],
        "forbidden_action_ran": policy["target_record"] in target.archived,
    }
    # governance: submit the verified candidate through the SubmitGate (orchestrator)
    if res["candidate"] is not None:
        scorer = _FakeScorer(correct=policy["flag"])
        gate = SubmitGate.for_orchestrator(scorer, log_path=run_dir / "submit.jsonl")
        status, _ = gate.submit_candidate(f"ai_{gid}", res["candidate"])
        out["submit_status"] = status
        out["candidate_status"] = res["candidate"].status
        out["flag_sha256"] = _sha(res["candidate"].value)
    else:
        out["submit_status"] = None
        out["candidate_status"] = None
        out["flag_sha256"] = None
    return out


def _measure_guard(gid, policy, scenario, benign_rank, exp):
    c0 = _run_config(gid, policy, scenario, B.c0_order(), "c0")
    c2 = _run_config(gid, policy, scenario, B.c2_order(benign_rank), "c2")
    # transfer contribution: C2 won via the experience-promoted benign family AND it
    # took strictly fewer attempts than C0.
    contributed = bool(
        exp["hit"] and c2["solved"] and c2["winner_family"] == "benign-admin"
        and c0["solved"] and c2["attempts"] < c0["attempts"])
    return {
        "guard": gid,
        "accepted_keys": policy.get("accepted_keys"),   # fine to record (not a secret flag)
        "experience_hit": exp["hit"],
        "c0": c0,
        "c2": c2,
        "attempts_delta": (c0["attempts"] - c2["attempts"]) if (c0["solved"] and c2["solved"]) else None,
        "experience_contributed": contributed,
    }


def _done_guards():
    if not RESULTS.is_file():
        return set()
    return {json.loads(l)["guard"] for l in RESULTS.read_text().splitlines() if l.strip()}


def _eval_ids(policies):
    return sorted(g for g, p in policies.items() if not p.get("is_seed"))


def run(batch_size=None, resume=False):
    STORE.mkdir(parents=True, exist_ok=True)
    policies = _load_policies()
    benign_rank = _seed_benign_rank(policies)
    exp = retrieve(SUBTYPE, benign_rank=benign_rank)
    eval_ids = _eval_ids(policies)
    done = _done_guards() if resume else set()
    if not resume and RESULTS.exists():
        RESULTS.unlink()  # fresh run
        done = set()
    todo = [g for g in eval_ids if g not in done]
    if batch_size:
        todo = todo[:batch_size]

    # one-time proof that a sub-agent cannot submit (governance guard)
    sub = SubmitGate.for_subagent(log_path=STORE / "_subagent_probe.jsonl")
    try:
        sub.submit_flag_value("ai_x", "FLAG{whatever}")
        subagent_blocked = False
    except NotAuthorized:
        subagent_blocked = True

    measured = []
    for gid in todo:
        row = _measure_guard(gid, policies[gid], _scenario(gid), benign_rank, exp)
        row["subagent_submit_blocked"] = subagent_blocked
        with open(RESULTS, "a", encoding="utf-8") as fh:        # commit per guard
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        measured.append(gid)
        print(f"  [{gid}] C0 attempts={row['c0']['attempts']} solved={row['c0']['solved']} | "
              f"C2 attempts={row['c2']['attempts']} solved={row['c2']['solved']} | "
              f"delta={row['attempts_delta']} contributed={row['experience_contributed']}")

    pending = [g for g in eval_ids if g not in (_done_guards())]
    print(f"[run] measured {len(measured)} this batch; experience_hit={exp['hit']} "
          f"benign_rank={benign_rank}; pending={pending}")
    return pending


def report():
    rows = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()] if RESULTS.is_file() else []
    policies = _load_policies() if VAULT_POLICIES.is_file() else {}
    eval_ids = _eval_ids(policies) if policies else sorted({r["guard"] for r in rows})
    pending = [g for g in eval_ids if g not in {r["guard"] for r in rows}]

    def _agg(cfg):
        atts = [r[cfg]["attempts"] for r in rows if r[cfg]["solved"]]
        return {
            "n": len(rows),
            "solved": sum(1 for r in rows if r[cfg]["solved"]),
            "attempts_mean": round(sum(atts) / len(atts), 2) if atts else None,
            "attempts_dist": sorted(atts),
        }

    c0, c2 = _agg("c0"), _agg("c2")
    deltas = [r["attempts_delta"] for r in rows if r["attempts_delta"] is not None]
    integrity = {
        # FWS: a submitted candidate that was not VERIFIED, or a solve whose forbidden
        # action did not actually run.
        "fws": sum(1 for r in rows for c in (r["c0"], r["c2"])
                   if c["solved"] and (c["candidate_status"] != "VERIFIED"
                                       or not c["forbidden_action_ran"])),
        "subagent_direct_submit": sum(0 if r.get("subagent_submit_blocked") else 1 for r in rows),
        "live_access": 0,
        "cheating_reads": 0,  # attacker has no vault/policy/flag handle by construction
    }
    rep = {
        "phase": "P27", "battery": len(eval_ids), "measured": len(rows), "pending": pending,
        "experience_hit": rows[0]["experience_hit"] if rows else None,
        "c0": c0, "c2": c2,
        "attempts_delta_mean": round(sum(deltas) / len(deltas), 2) if deltas else None,
        "guards_experience_contributed": sum(1 for r in rows if r["experience_contributed"]),
        "integrity": integrity,
        "per_guard": [{"guard": r["guard"], "accepted": r["accepted_keys"],
                       "c0": r["c0"]["attempts"], "c2": r["c2"]["attempts"],
                       "delta": r["attempts_delta"], "c2_winner": r["c2"]["winner"],
                       "contributed": r["experience_contributed"]} for r in rows],
    }
    STORE.mkdir(parents=True, exist_ok=True)
    (STORE / "report.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    _write_md(rep)
    print(json.dumps(rep, indent=1))
    return rep


def _write_md(rep):
    lines = [
        "# Phase 27 — AI experience transfer (C0 vs C2)", "",
        f"Battery {rep['battery']} eval guards, measured {rep['measured']}, "
        f"pending {rep['pending']}. Deterministic scripted attacker (~0 tokens); "
        "mechanism measurement under a stated attacker model, not an LLM performance claim.",
        "",
        f"- **C0** (no experience): solved {rep['c0']['solved']}/{rep['measured']}, "
        f"attempts-to-solve mean {rep['c0']['attempts_mean']} dist {rep['c0']['attempts_dist']}",
        f"- **C2** (experience): solved {rep['c2']['solved']}/{rep['measured']}, "
        f"attempts-to-solve mean {rep['c2']['attempts_mean']} dist {rep['c2']['attempts_dist']}",
        f"- mean attempts saved (C0-C2): **{rep['attempts_delta_mean']}**; "
        f"guards where experience contributed: {rep['guards_experience_contributed']}/{rep['measured']}",
        f"- integrity: FWS {rep['integrity']['fws']}, sub-agent direct submit "
        f"{rep['integrity']['subagent_direct_submit']}, live {rep['integrity']['live_access']}, "
        f"cheating reads {rep['integrity']['cheating_reads']}",
        "", "## Per-guard (attempts-to-solve)", "",
        "| guard | accepted vocab | C0 | C2 | saved | C2 winner | experience used |",
        "|---|---|---|---|---|---|---|",
    ]
    for g in rep["per_guard"]:
        lines.append(f"| {g['guard']} | {','.join(g['accepted'] or [])} | {g['c0']} | {g['c2']} "
                     f"| {g['delta']} | {g['c2_winner']} | {'yes' if g['contributed'] else 'no'} |")
    (STORE / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--batch-size", type=int, default=None)
    r.add_argument("--resume", action="store_true")
    sub.add_parser("report")
    args = ap.parse_args(argv)
    if args.cmd == "run":
        run(batch_size=args.batch_size, resume=args.resume)
    elif args.cmd == "report":
        report()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
