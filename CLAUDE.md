# ctf_agent_v3 — operating rules

## Always route CTF work through the managed framework

When given a CTF challenge, a challenge file/directory, a target URL, or a CTFd
instance (with or without a token), **always route it through the managed framework** —
never hand-solve outside it. There are two sanctioned entry points for the two jobs:

**Solving defaults to the `ctf-solve` skill (the session-orchestrated agent method).**
A freeform "풀어줘 / solve this" uses it: this session acts as orchestrator and, per
challenge, spawns a real solver sub-agent that reasons from the injected `skill_pack`
and runs experiments via the category sandbox harness (`solver/<cat>_harness.py`) —
collect (connector) → classify/triage/route → sub-agent solve → reproduce → verify →
candidate surfaced for MANUAL submit. This is the promoted P34 method and is the
default engine; the sub-agent consumes the knowledge packs (the scripted CM path does
not). See `.claude/skills/ctf-solve/SKILL.md`.

**Collection / plan / scripted baseline = `solve.py`:**

```
python3 solve.py <input> [--bench] [--ctfd] [--run]
```

`solve` auto-detects the input (CTFd / URL / directory / file) and drives the shared
core. Use it to collect from a CTFd, to print the routing plan, or as the deterministic
non-LLM baseline (`--run` = scripted CM solvers, no model in the loop). The agent method
reuses the same framework pieces (connector · triage/router · skill_pack · harness ·
StopLoss · verifier · SubmitGate · writeup) — it orchestrates them with a solver
sub-agent instead of the scripted driver.

**Never solve ad-hoc.** "Ad-hoc" = bypassing the framework: raw scratch directories
(e.g. `ctf_work/`) with tools hand-run on the host, no sandbox, no budget, no evidence,
no writeup. Driving sub-agents per the `ctf-solve` skill is NOT ad-hoc — it runs every
experiment inside the category sandbox harness with the same budget/evidence/governance.
The WHITEHAT qualifier retrospective (Phase R) showed ad-hoc work loses budget
discipline, checkpoint/resume, evidence capture, and the disclosure writeup log.

## Modes — contest is the default, bench is opt-in

- **contest (default):** a real competition. Network to the challenge target is
  allowed; no vault (verify by server / flag format); goal = maximise solves within
  budget. This is what a freeform "풀어줘 / solve this" must use.
- **bench (`--bench` only):** the blind honest-measurement mode — `--network none`,
  blind vault + scorer key. Enter it **only on explicit request**. Its behaviour and
  the governance files are frozen (see below); do not change them to serve contest.

## Governance invariants (do not touch to serve contest mode)

These 7 files are hash-pinned in `growth/governance_baseline.txt` and must stay
byte-identical; `sha256sum -c growth/governance_baseline.txt` must pass:
`orchestrator/skill_pack.py`, `connector/submit_gate.py`, `solver/verifier.py`,
`tools/web_service.py`, `tools/pwn_service.py`, `tools/sandbox.py`,
`config/sandbox.json`.

## Submission

Never auto-submit to a contest server. Surface the candidate flag + evidence to the
user for manual submission (contest rules). No brute/repeat spray at any server.
