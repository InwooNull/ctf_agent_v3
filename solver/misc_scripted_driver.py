"""Scripted (non-LLM) driver for Misc/Forensics: runs ONE given solve script
through the MiscHarness (inside ctfagent-misc:0.1, --network none), reads the
candidate back from the container stdout, and reports it with that experiment
as evidence.

The driver holds no per-challenge knowledge; the solve script is passed in (the
reference solvers live in vault/ref_misc.py). A candidate is reported only when
the script printed `CANDIDATE <flag>` — i.e. the flag was derived from the
challenge file by the toolchain inside that same experiment.
"""
import re

from solver.misc_harness import MiscHarness

# Any flag format: a token with a {...} body (NYU real flags are lowercase flag{},
# the synthetic set uses FLAG{}). The solver only ever prints validated flags.
CAND_RE = re.compile(r"^CANDIDATE (\S+\{[^}\s]*\})\s*$", re.M)


def solve(challenge_dir, run_id, code, hypothesis, store_root=None, timeout=120):
    """Returns (harness, outcome, reported_flag or None)."""
    h = MiscHarness(run_id, challenge_dir, store_root=store_root)
    h.record_hypothesis(hypothesis, priority_band="high")
    outcome = h.run_experiment({"name": "solve", "code": code, "timeout": timeout})
    m = CAND_RE.search(outcome.stdout or "")
    flag = m.group(1) if m else None
    if flag:
        h.report_candidate(flag, [outcome.exp_id])
    return h, outcome, flag
