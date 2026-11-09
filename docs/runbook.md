# Finals runbook — running the agent end-to-end

How to run this agent in a live competition. The integrated run is **session-orchestrated**:
`orchestrator/competition.py` is the policy *layer* (a pure-Python loop) and **cannot spawn
LLM sub-agents** — the real solving is driven by the session (this Claude Code session),
which reuses the policy *objects* (`Scheduler`, `StopLoss`, `triage`, `SubmitGate`) and
spawns one real sub-agent per challenge. Phase 34 proved this works end-to-end.

## 0. Preconditions
- Images present: `ctfagent-{crypto,pwn,rev,web,misc,mlsec}` (misc finals image = **0.2**, has
  `7z`; see docker/Dockerfile.misc2). `docker images | grep ctfagent`.
- Secrets: `config/acdc.env` (chmod 600, git-ignored) with the platform URL/creds/token.
- Full suite green: `python3 -m unittest discover -s tests`.

## 1. Fetch (connector)
    python3 -m connector.fetch            # CTFd -> arena/live/<cid>/ + store/live/manifest.json
Session-cookie auth + Origin/Referer are handled by `connector/ctfd_client.py`. KOTH/livefire
are separate (not flag-submit). Downloaded files are untrusted (own dir, never executed from).

## 2. Classify + schedule
- `orchestrator.classifier.classify` → category; `router.route` → lane.
- Build `orchestrator.scheduler.Scheduler(challenges, global_caps={time_s, experiments})`;
  priority = (score ÷ difficulty-weight) ÷ est_cost. Work `scheduler.next()` best-first.

## 3. Per challenge (session loop)
For the challenge `scheduler.next()` picks:
1. Prepare its category run dir (blind): the category runner/CLI (`arena/<cat>_cli.py`),
   flags staged to vault / 2-uid `_boot` (pwn), vault **locked**, atime-trap armed.
2. Spawn ONE real sub-agent with the category C0 prompt; it drives ONLY
   `arena/<cat>_cli.py <run_id> {info|exp|report|give_up|status}` (CLI-only, blind).
3. Track `StopLoss`: per-challenge budget = the CLI's exp/wall cap. On give-up/exhaust =
   **손절**, mark done, move to the next. (Near-miss budget-raise = a re-spawn with more
   budget only if a verified chain is held — expensive; use sparingly.)
4. Verify (scorer + CLI-only transcript audit + trap) → 3-bucket (SOLVED/FAILED/BLOCKED).
5. If a candidate was reported: **triage.is_decoy** (reject SAMPLE/placeholder/no-evidence)
   → **reproduce-before-submit** (replay the WINNING experiment in a clean, history-free run;
   must re-derive the same flag) → **SubmitGate.submit_candidate** → platform.

## 4. Submission governance (never bypass)
- Only the orchestrator submits. **Sub-agents can never submit** — a sub-agent `SubmitGate`
  holds no client and raises `NotAuthorized`. Candidates are reported, the orchestrator decides.
- Gate enforces, in order: role → evidence chain (VERIFIED + evidence_refs) → decoy screen →
  reproduce → dup/already-solved → per-challenge attempt cap → 429 backoff → append-only
  sha256 log (`store/live/submissions.jsonl`). State replays from the log ⇒ crash/restart never
  double-submits. Never log the flag in clear.

## 5. Rate-limit / retry / resume / zombies (checklist)
- [ ] 429: `connector/retry.py` escalating backoff (15→30→45→70 s + settle); honor server retry_after.
- [ ] challenge-server `system_error`/`provider_failed`: flat 32 s gap, retry same request.
- [ ] network/DNS blip (EAI_AGAIN): `retry_network()` retries blips, re-raises hard errors.
- [ ] challenge-server single-in-flight: `chalsrv` wait_idle → POST once → poll by id (no re-POST).
- [ ] CTFd session closed mid-run → one re-login, resume the same request.
- [ ] Containers run `--rm`; after a batch, `docker ps -aq --filter name=ctfagent_` should be empty.
- [ ] Resume: verify/submit skip already-done cids; SubmitGate log makes submit idempotent.

## 6. SEQUENTIAL execution constraint (important)
Each category's vault lock also locks the **sibling** blind dirs (so a blind agent can't read
another run's flag/baseline). Consequence: **run categories sequentially**, not blind-concurrent —
prepare→spawn→verify→submit one category, then hand off the lock (unlock) before the next.
Challenges *within* one category/config can run in parallel (independent containers). Always
re-lock the vault when done (`...runner lock <cfg>`); confirm `lockstate`.

## 7. "Weakness found → fix" procedure (mid-competition)
1. Reproduce the failure offline with a deterministic/synthetic fixture (never on the live target).
2. Fix in `~/ctf_agent_v3`; add a regression test; `python3 -m unittest discover -s tests` green.
3. Keep blindness/anti-cheat invariant (agent uid can't read the flag; CLI-only audit clean; trap []).
4. Only then resume the live run. Record the fix in `docs/findings.md`.

## Holdout sets (blind) available
- pwn: `arena/real_pwn` (rp_*) + `vault/scorer_keys_pwn_real` + `manifest_pwn_real.json`.
- misc/forensics: `arena/real_misc` (mr_*) + `vault/scorer_keys_misc_real`.
- rev: `arena/real_rev` (rr_*) + `vault/scorer_keys_real` + `manifest_real.json` (20 holdout / 9 dev).
- web: `arena/real_web` (+ `scorer_keys_web_real`).
- crypto: **no real holdout** — the NYU bench ships no crypto category; crypto is synthetic only
  (`eval/make_dev_*`). A real crypto baseline/C1 is not available from the current materials.
- AI/mlsec: synthetic only (`vault/gen_ai*`, `vault/gen_mlsec.py`); real AI challenges are
  server/LLM-dependent (see docs/ai_recon.md), a separate API-budget decision.
