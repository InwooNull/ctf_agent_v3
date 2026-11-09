"""Phase 44c end-to-end demo (offline, token-free): one GrowthLoop cycle where the
sequential gate ADOPTS one improvement and ROLLS BACK another, proving the regression
gate stops drift while keeping a genuinely good change.

Synthetic + deterministic: run_batch is a stub (no solver, no tokens); the managed
surface is one temp cheatsheet file; dev/holdout "grading" is driven by file content so
every change's effect is reproducible, the way a --network none fixed-input run would be.
No vault, no scorer key, no governance file touched.

  python3 eval/p44c_demo.py        # -> store/p44_growth/demo_cycle.json
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
from growth.surface import Surface  # noqa: E402

OUT = PROJECT_ROOT / "store" / "p44_growth"
DEV = ["d_fix", "d_noise"]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    cheats = tmp / "skills.md"
    cheats.write_text("BASE\n")                 # the managed AUTO surface
    surface = Surface([cheats])

    # both dev challenges FAILED this batch; the (stubbed) self-judgment calls both
    # knowledge_gap with high confidence (an AUTO bucket).
    def run_batch(dev):
        return BatchResult(runs=[
            RunOutcome(c, outcome="GIVE_UP", solved=False, category="crypto",
                       signals={"give_up_kind": "analysis"}) for c in dev])
    judge = lambda s, e: ("knowledge_gap", 0.9)   # residual -> confident AUTO

    # dev grading: d_fix needs token FIX, d_noise needs token FIX2
    dev_needs = {"d_fix": "FIX", "d_noise": "FIX2"}
    def dev_eval(cids):
        txt = cheats.read_text()
        return {c: (dev_needs[c] in txt) for c in cids}
    # holdout grading: 2 members pass while the cheatsheet is not corrupt
    def holdout_eval():
        ok = "CORRUPT" not in cheats.read_text()
        return {"h1": ok, "h2": ok}

    # drafter: d_fix -> a clean fix (flips its target, holdout fine) => ADOPT
    #          d_noise -> flips its own target BUT corrupts the sheet (holdout drop) => ROLLBACK
    def drafter(diag, runs, successes):
        cid = diag["cid"]
        if cid == "d_fix":
            def mut(_s): cheats.write_text(cheats.read_text() + "FIX\n")
            return Improvement("imp-d_fix", "knowledge_gap", ["d_fix"], mut,
                               describe="add the missing technique note (clean)")
        if cid == "d_noise":
            def mut(_s): cheats.write_text(cheats.read_text() + "FIX2\nCORRUPT\n")
            return Improvement("imp-d_noise", "knowledge_gap", ["d_noise"], mut,
                               describe="a change that fixes its target but regresses holdout")
        return None

    regressor = Regressor(dev_eval, holdout_eval)
    improver = Improver(surface, regressor, drafter=drafter)
    diagnoser = Diagnoser(judge=judge)

    loop = GrowthLoop(OUT / "demo_run", run_batch=run_batch,
                      diagnoser=diagnoser, improver=improver)
    rep = loop.cycle(DEV)

    report = {
        "what": ("Phase 44c sequential gate demo — one adopt, one rollback. Offline, "
                 "token-free, no vault/governance touched."),
        "cycle": rep.to_dict(),
        "n_adopted": len(rep.improvements_applied),
        "n_rolled_back": len(rep.improvements_rolled_back),
        "final_cheatsheet_has_FIX": "FIX\n" in cheats.read_text(),
        "final_cheatsheet_has_CORRUPT": "CORRUPT" in cheats.read_text(),
    }
    (OUT / "demo_cycle.json").write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return report


if __name__ == "__main__":
    main()
