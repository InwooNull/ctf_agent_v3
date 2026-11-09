"""Scripted (non-LLM) driver for Reverse: runs ONE given solve script through the
RevHarness (inside ctfagent-rev:0.1, --network none), reads the candidate back from
the container stdout, and reports it with that experiment as evidence.

The driver holds no per-challenge knowledge; the solve script is passed in (the
reference solvers live in vault/ref_rev.py). A candidate is reported only when the
script printed `BINARY_ACCEPTS`, i.e. the binary itself accepted the derived input
inside the same experiment.
"""
import re

from solver.rev_harness import RevHarness

CAND_RE = re.compile(r"^CANDIDATE (FLAG\{[^}\s]*\})$", re.M)


def solve(challenge_dir, run_id, code, hypothesis, store_root=None, timeout=120):
    """Returns (harness, outcome, reported_flag or None)."""
    h = RevHarness(run_id, challenge_dir, store_root=store_root)
    h.record_hypothesis(hypothesis, priority_band="high")
    outcome = h.run_experiment({"name": "solve", "code": code, "timeout": timeout})
    m = CAND_RE.search(outcome.stdout or "")
    flag = m.group(1) if m and "BINARY_ACCEPTS" in outcome.stdout else None
    if flag:
        h.report_candidate(flag, [outcome.exp_id])
    return h, outcome, flag
