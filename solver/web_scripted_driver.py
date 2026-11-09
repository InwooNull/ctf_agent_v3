"""Scripted (non-LLM) driver for Web: runs ONE given exploit through the
WebServiceHarness (one 2-uid --network none container, target reachable only
over the loopback HTTP tube), reads the candidate back from the container
stdout, and reports it with that experiment as evidence.

The driver holds no per-challenge knowledge; the exploit is passed in (the
reference exploits live in vault/ref_web.py). A candidate is reported only when
the exploit printed `CANDIDATE <flag>` — i.e. the flag was derived from the live
app through its bug inside that same experiment.

Flag staging (eval/runner side): the per-run flag is written to the boot path
WebServiceHarness._boot_flag() reads (`<set>/_boot/<run_id>/flag`). The exploit
code never receives it; the boundary injects it into the app's environment only.
This mirrors how the real C0 runner will stage boot flags.
"""
import re
from pathlib import Path

from solver.web_harness import WebServiceHarness

CAND_RE = re.compile(r"^CANDIDATE (\S+\{[^}\s]*\})\s*$", re.M)


def solve(challenge_dir, store_set, run_id, code, hypothesis, flag, timeout=90):
    """Stage the boot flag, run `code` on the boundary, report any CANDIDATE.

    `store_set` is the set dir; the harness run dir is `<store_set>/<run_id>/harness`
    and the boot flag is staged at `<store_set>/_boot/<run_id>/flag`.
    Returns (harness, outcome, reported_flag or None)."""
    store_set = Path(store_set)
    boot = store_set / "_boot" / run_id
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "flag").write_text(flag)

    h = WebServiceHarness("harness", challenge_dir, store_root=store_set / run_id)
    h.record_hypothesis(hypothesis, priority_band="high")
    outcome = h.run_experiment({"name": "solve", "code": code, "timeout": timeout})
    m = CAND_RE.search(outcome.stdout or "")
    reported = m.group(1) if m else None
    if reported:
        h.report_candidate(reported, [outcome.exp_id])
    return h, outcome, reported
