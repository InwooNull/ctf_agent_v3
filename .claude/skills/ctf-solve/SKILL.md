---
name: ctf-solve
description: >
  The DEFAULT engine for solving a CTF when the user gives a challenge file/dir, a
  target URL, or a CTFd instance (± token) and says "풀어줘 / solve this". Promotes the
  P34 session-orchestrated multi-agent method to the default: this session acts as the
  ORCHESTRATOR, reusing the built framework (connector · classifier/triage · skill_pack ·
  category sandbox harnesses · Scheduler/StopLoss/SubmitGate/verifier), and spawns a real
  solver sub-agent per challenge that iterates with the tools/skills to find the flag.
  Use whenever a CTF input appears — this, not the scripted CM path, is the default.
---

# ctf-solve — agent-default contest engine (session-orchestrated)

This is the promotion of the method the project already built and proved in Phase 34:
**the session orchestrates and spawns real sub-agents that solve on the framework.** The
scripted CM path (`solve.py --run` → `contest_run` → scripted drivers) stays as a
deterministic baseline; it is NOT this. Here an LLM sub-agent per challenge actually
consumes the `skill_pack` knowledge and drives the category harness in the sandbox.

## Non-negotiable invariants (restate in every sub-agent brief)
- **Governance files are frozen.** Never edit the 7 hash-pinned files
  (`orchestrator/skill_pack.py`, `connector/submit_gate.py`, `solver/verifier.py`,
  `tools/web_service.py`, `tools/pwn_service.py`, `tools/sandbox.py`,
  `config/sandbox.json`). `sha256sum -c growth/governance_baseline.txt` must still pass.
- **Never auto-submit.** Contest mode surfaces the candidate + evidence to the USER for
  manual submission. A sub-agent is constructed with `SubmitGate.for_subagent(...)` which
  raises `NotAuthorized` on any submit — only the orchestrator (this session) handles
  candidates, and even then it does not hit a contest server.
- **No-guess / evidence-grounded.** A flag is reportable ONLY when a real in-sandbox
  execution output or target response produced it (SRC_EXEC / SRC_TARGET). Never report a
  guessed, pattern-matched, or theme-inferred flag. On StopLoss no-progress, give up
  cleanly — a clean give-up is a valid outcome, not a failure to paper over.
- **Security — untrusted inputs.** Challenge files are untrusted. Never run a challenge's
  own code on the host. ALL execution happens inside the category harness
  (`solver/<cat>_harness.py`, which uses the `ctfagent-<cat>` image + project sandbox,
  `--network none` for file challenges). Keep each challenge's files in its own dir; keep
  the sub-agent's own scripts separate; pass paths as arguments.

## Phase 0 — Collect (orchestrator)
Detect the input and gather challenges, reusing the connector (do not re-implement):
- **CTFd URL/token** → `connector.ctfd_client.CTFdClient` (`.list_challenges()`,
  `.get_challenge(id)`, `.download_file(url)`), or `solve.py <url> --ctfd` for the managed
  collect. Download each challenge's files into its own isolated dir.
- **local dir/file** → use it directly as the challenge dir.
- **plain target URL** → a single live web/service challenge (networked; see Phase 2 net).
Record, per challenge: `id`, `category` (filled in Phase 1), `flag_format` (default
`flag{...}`; CTFd/known platform format when provided), the challenge dir, and any remote
target (`nc host port` / URL).

## Phase 1 — Triage & route (orchestrator)
Per challenge: `orchestrator.triage.first_pass(dir)` for the quick signal + cheap-win
screen, `orchestrator.classifier.classify(challenge)` → category, `orchestrator.router.route(category)`.
Load the knowledge pack text with `orchestrator.skill_pack.load_pack(category)` (this is
what the sub-agent will reason from). Order the queue with `orchestrator.scheduler.Scheduler`
(flags-per-hour: score ÷ difficulty-weight ÷ est_cost). Watch for decoys
(`orchestrator.triage.is_decoy`).

## Phase 2 — Solve: spawn one sub-agent per challenge (the core)
For each challenge in Scheduler order, spawn a solver sub-agent (Agent tool). Brief it with:
1. **The challenge** — its isolated dir (read-only inputs), flag_format, and for a net
   challenge the scoped target (reachable only through the egress policy; loopback/declared
   target only).
2. **The injected knowledge** — paste `skill_pack.load_pack(category)`. It is background
   capability knowledge (which technique fits which observation), NOT a lowering of the
   no-guess bar.
3. **Its tool = the category harness.** The sub-agent solves by a ReAct loop:
   observe → form a hypothesis from the pack → write a short experiment (its OWN python,
   `-I`) → run it via `solver.<cat>_harness.<Cat>Harness(run_id, challenge_dir).run_experiment(
   {"name":..., "code":..., "timeout":..., "nondeterministic":False})` (this executes inside
   the `ctfagent-<cat>` sandbox, isolated) → read stdout → refine. The flag must appear in a
   captured experiment stdout (that stdout is the evidence). Categories & harnesses:
   `crypto`→CryptoHarness (gmpy2/pycryptodome/sympy/z3), `rev`→RevHarness (angr, in
   `ctfagent-rev`), `pwn`→PwnHarness / pwn_service_harness (local binary 2-uid boundary;
   remote = NON-WEAPONIZING benign interaction only, exploit-dev is out of scope — log and
   give up honestly), `web`→WebHarness, `misc`→MiscHarness. **Live web targets only**
   (contest-mode plain target URL / a reachable CTFd service, NOT the `--network none`
   file-challenge harness, whose loopback target the host cannot reach): the sub-agent may
   additionally drive the **Burp MCP** tools (`mcp__burp__*`) from the orchestrator for
   mapping/replay (Repeater: `send_http1_request`/`create_repeater_tab`), fuzzing
   (`send_to_intruder`), reviewing captured traffic (`get_proxy_http_history`), and payload
   encoding (`base64_*`/`url_*`) — see `skills/web/SKILL.md` "Live-target lane (Burp MCP)".
   The no-guess bar is unchanged: the flag must still come from a real target response.
4. **The rules** — the four invariants above, verbatim. It returns: a candidate flag + the
   evidence ref (the exact experiment name + stdout that produced it), or an honest
   give-up with the failure diagnosis (approach / budget / tool_gap).
5. **StopLoss** — a per-challenge experiment/wall budget from
   `orchestrator.stoploss.caps_for(category)`: analysis-heavy categories (rev/misc) get
   more runway (~24 experiments), crypto/web/pwn stay tighter (12–16); the near-miss
   RAISE_ONCE still grants one extension when a verified chain is in hand. Brief the
   sub-agent with the category's cap so it paces probes and, when `StopLoss` signals
   no-progress, stops and hands back cleanly (a clean give-up is a valid outcome).

Keep sub-agents scoped and sequential where category vault/locks require it; otherwise a
few may run concurrently. Do NOT let a sub-agent submit or touch governance files.

## Phase 3 — Verify, gate, surface (orchestrator)
For each returned candidate, BEFORE surfacing:
- **Reproduce-before-submit** — replay the winning experiment history-free in a fresh
  harness run; it must reproduce the flag. A false-negative here is usually a path/dir
  issue, not a bad flag — check before discarding.
- **Verify evidence** — `solver.verifier.verify(run_dir, cid, ...)` style: candidate must
  be backed by a real execution/target output, not fabricated. `triage.is_decoy` to reject
  sample/decoy flags.
- **SubmitGate** — construct `connector.submit_gate.SubmitGate.for_orchestrator(...)`. In
  **contest mode do NOT submit to a server** — present `cid → candidate flag + evidence
  refs + confidence` to the USER for manual submission. (The gate still enforces: verified
  only, no duplicate, decoy-rejected, reproduction-passed.)
- **Writeup log** — record model + injected prompt + output per challenge for the
  disclosure log, as `contest_run`'s WriteupLog does.

## Output to the user
A per-challenge table: SOLVED (flag + evidence) / FAILED (honest give-up + diagnosis) /
BLOCKED, the candidate flags for manual submission, and where the evidence/writeup live.
Never claim a solve without its reproduced, evidence-grounded flag.

## Relation to `solve.py`
`solve.py` remains the sanctioned entrypoint for collection/plan and the scripted CM
baseline. This skill is the agent-default SOLVE engine layered on the same framework
pieces; it does not replace the connector, the harnesses, the policy objects, or the
governance — it orchestrates them with a real solver sub-agent in the loop.
