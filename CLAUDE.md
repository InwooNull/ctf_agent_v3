# ctf_agent_v3 — operating rules

## Always route CTF work through `solve` (the managed pipeline)

When given a CTF challenge, a challenge file/directory, a target URL, or a CTFd
instance (with or without a token), **always route it through the managed pipeline**:

```
python3 solve.py <input> [--bench] [--ctfd] [--run]
```

`solve` auto-detects the input (CTFd / URL / directory / file), picks the mode, and
drives the shared core (triage/router → category harness → skill_pack injection →
StopLoss → verifier/evidence capture → checkpoint/resume → writeup log).

**Never solve ad-hoc.** Do not create raw scratch directories (e.g. `ctf_work/`) and
hand-run tools outside the pipeline. The WHITEHAT qualifier retrospective (Phase R)
showed ad-hoc work loses all of: budget discipline, checkpoint/resume, evidence
capture, and the disclosure writeup log. The pipeline is the only sanctioned route.

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
