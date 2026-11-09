"""Phase 44d autonomous multi-cycle demo (offline, token-free, no vault/governance).

Runs GrowthLoop.run() for several chained cycles with ZERO human intervention and shows:
  * cycle chaining (one adoption carries into the next cycle's batch outcome),
  * the regression gate BLOCKING drift (a change that fixes its dev target but regresses
    holdout is rolled back every time it is retried),
  * convergence (net 0 adoption for k cycles -> stop_reason),
  * the final governance/isolation drift proof.

  python3 eval/p44d_demo.py        # -> store/p44_growth/autocycles.json
"""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from growth.loop import GrowthLoop, BatchResult, RunOutcome  # noqa: E402
from growth.diagnoser import Diagnoser  # noqa: E402
from growth.improver import Improver, Improvement  # noqa: E402
from growth.regress import Regressor  # noqa: E402
from growth.surface import Surface, sha256_bytes  # noqa: E402

OUT = PROJECT_ROOT / "store" / "p44_growth"
DEV = ["d1", "d2"]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    cheats = tmp / "skills.md"; cheats.write_text("BASE\n")
    surface = Surface([cheats])

    # d1 solves once FIX1 is in the cheatsheet; d2 would need FIX2 but its only draft also
    # corrupts the sheet (a holdout regression) -> the gate rolls it back forever.
    def rb(dev):
        txt = cheats.read_text()
        runs = []
        for c in dev:
            solved = ("FIX1" in txt) if c == "d1" else ("FIX2" in txt)
            runs.append(RunOutcome(c, "SOLVED" if solved else "GIVE_UP", solved,
                                   signals={} if solved else {"give_up_kind": "analysis"}))
        return BatchResult(runs=runs)

    def drafter(d, runs, succ):
        cid = d["cid"]
        if cid == "d1":
            def m(_s): cheats.write_text(cheats.read_text() + "FIX1\n")
            return Improvement("imp-d1", "knowledge_gap", ["d1"], m, describe="clean technique note")
        if cid == "d2":
            def m(_s): cheats.write_text(cheats.read_text() + "FIX2\nCORRUPT\n")
            return Improvement("imp-d2", "knowledge_gap", ["d2"], m, describe="fixes target but regresses holdout")
        return None

    needs = {"d1": "FIX1", "d2": "FIX2"}
    reg = Regressor(lambda cs: {c: needs[c] in cheats.read_text() for c in cs},
                    lambda: {"h1": "CORRUPT" not in cheats.read_text(),
                             "h2": "CORRUPT" not in cheats.read_text()})
    loop = GrowthLoop(OUT / "auto_run", run_batch=rb, diagnoser=Diagnoser(judge=lambda s, e: ("knowledge_gap", 0.9)),
                      improver=Improver(surface, reg, drafter=drafter),
                      no_progress_k=2, max_cycles=6)
    reports = loop.run(DEV)

    gov = (PROJECT_ROOT / "growth" / "governance_baseline.txt").read_text().splitlines()
    drift = []
    for line in gov:
        if line.strip():
            h, rel = line.split()
            drift.append({"file": rel, "matches_baseline": sha256_bytes((PROJECT_ROOT / rel).read_bytes()) == h})

    out = {
        "what": ("Phase 44d autonomous chained cycles (offline/token-free). Skeleton + "
                 "safety validation only; the first REAL blind-runner autonomous run is a "
                 "separate later milestone."),
        "cycles": [r.to_dict() for r in reports],
        "n_cycles": len(reports),
        "stop_reason": reports[-1].stop_reason,
        "total_adopted": sum(len(r.improvements_applied) for r in reports),
        "total_rolled_back": sum(len(r.improvements_rolled_back) for r in reports),
        "drift_blocked_example": next(
            (rb for r in reports for rb in r.improvements_rolled_back), None),
        "final_cheatsheet": cheats.read_text(),
        "governance_drift_check": drift,
        "governance_all_match": all(d["matches_baseline"] for d in drift),
    }
    (OUT / "autocycles.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in ("n_cycles", "stop_reason", "total_adopted",
                                          "total_rolled_back", "final_cheatsheet",
                                          "governance_all_match")}, indent=1))
    print("drift_blocked_example:", json.dumps(out["drift_blocked_example"])[:220])
    return out


if __name__ == "__main__":
    main()
