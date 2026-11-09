# Phase 34 — integration rehearsal (real LLM, mixed holdout): results + friction list

The whole agent run end-to-end on a mixed set with **real LLM solving**: the session
orchestrates (Scheduler / StopLoss / triage / SubmitGate as live policy objects) and a
real sub-agent per challenge solves blind on the category CLI; candidates then go
triage → reproduce-before-submit → SubmitGate → mock_ctfd. Platform = `connector.mock_ctfd`
(no live competition). Small, mixed, sanity integration — **no performance claim**.

## Set (8 challenges, 3 harnesses; crypto unavailable — see friction #1)
misc (plain container): leaked_flag, simple_recovery, showdown(decoy) ·
pwn (2-uid boundary): baby_boi, WarmUp, horrorscope(P33-deployable) ·
rev (container, **synthetic** r7_* set — see friction #2): r7_099e2f, r7_0b1253

## Result — 3 buckets (store/p34_rehearsal/report.json)
| category | SOLVED | FAILED | mock_ctfd scored | notes |
|---|---|---|---|---|
| misc | 1 | 2 | [2] | simple_recovery solved (RAID5→XMP); showdown/leaked_flag = remote-misclassified, correct give-ups |
| pwn  | 2 | 1 | [1,2] | baby_boi (ret2libc) + WarmUp (ret2win) solved; horrorscope deployed+live-interacted, capability-bound |
| rev  | 2 | 0 | [1,2] | both crackmes solved (static recovery, verified by running the binary) |
| **all** | **5** | **3** | — | 0 BLOCKED |

Every SOLVED flag passed a **clean reproduce-replay** (history-free re-execution of the
winning experiment) before submit, then SubmitGate → mock_ctfd returned **correct** for
all 5. Integrity: **FWS 0, non-container 0, trap_hits [] (blind held), sub-agent direct
submit blocked in all 3 categories.** Two transcripts flagged non-clean
(mr_73bb9c, r7_099e2f) are benign (one FAILED, one SOLVED with trap-clean) — same kind
of benign audit artifact seen in Phase 22; neither accessed a secret.

## Policies that fired live
- **Scheduler (flags-per-hour):** processed each category in priority order
  (score ÷ difficulty-weight ÷ est_cost); recorded per batch.
- **Reproduce-before-submit:** replayed each winning exploit/solve in a fresh
  environment; a real **false-negative was caught and fixed mid-run** (it looked in the
  wrong dir — see friction #3), after which all 5 solves reproduced and submitted.
- **SubmitGate → mock_ctfd:** 5/5 submitted flags scored `correct`; sub-agent gate
  raised `NotAuthorized` in every category.
- **triage decoy:** showdown ships `THIS IS A SAMPLE FLAG`; the agent correctly refused
  to report the sample (no candidate), and the decoy screen would have rejected it had it
  been reported.
- **StopLoss (손절):** per-challenge budget was the CLI's; give-up/exhaust = stop and move
  to the next (scheduler). The orchestrator-level near-miss budget-raise was NOT exercised
  (it needs a re-spawn; out of scope for cost here) — noted.

## What was smooth
- Per-category harnesses + CLIs + the P8/c0b verify machinery plugged into the
  orchestration unchanged; blind + CLI-only audit + atime-trap held throughout (trap []).
- Reproduce-replay worked across all three harnesses (misc LZMA re-decode, pwn exploit
  re-run on a fresh 2-uid boundary, rev re-derivation).
- The P33 boundary fix was validated **in-situ**: horrorscope now boots and the agent
  interacted with the live service (it failed only on glibc-2.34 weaponization, not
  deployment) — the clean "deploy-OK ≠ capability" separation.

## Friction list (fix before finals)
1. **No crypto blind arena.** The real crypto holdout was never loaded into a blind
   arena (`arena/real_crypto` is empty), so crypto could not be integrated. → load a
   crypto holdout + scorer keys + a `crypto_cli` p34 route.
2. **Rev holdout not keyed.** `arena/real_rev` (rr_*) has no scorer keys/manifest; only
   the **synthetic** Phase-8 set (r7_*, `arena/rev_instances`) is keyed, so rev here is a
   synthetic (high-contamination) 3rd-harness check, not a holdout measure. → key/load the
   real rev holdout.
3. **Reproduce-gate dir path (FIXED).** `_winning_code` looked in `<run>/work/...` but the
   CLI nests the harness under `<run>/harness/...`; this falsely blocked a genuine solve
   until fixed. Generalized to search both.
4. **pwn per-exp code not persisted (FIXED).** The 2-uid boundary overwrote `work/exp.py`
   each run, so a clean reproduce-replay could not recover the winning exploit. Now each
   experiment's code is saved to `exp_code/<name>.py`.
5. **misc image lacks `7z`.** simple_recovery had to hand-decode LZMA2 in pure Python
   (succeeded, but wasteful). → add `p7zip` to `ctfagent-misc`.
6. **Scheduler item key mismatch (FIXED).** The set used `cid`; `Scheduler` expects `id`.
7. **Per-category lock handoff.** Each category's vault lock sibling-locks the other p34
   dirs, so categories run **sequentially** (can't be blind-concurrent) and report/submit
   must cycle unlock→lock. Acceptable, but a unified lock would simplify a finals run.
8. **Orchestration is session-driven.** `competition.py` (pure Python) cannot spawn LLM
   sub-agents; the integrated real-LLM run is driven by the session reusing the policy
   *objects* + real sub-agents. This is inherent — the finals loop is session-orchestrated,
   not `competition.run()`.

## Verdict
The integrated pipeline **works end-to-end with real LLM solving** across three different
harnesses, with every governance invariant intact and the Phase-33 fix validated in-situ.
The rehearsal's purpose — prove integration + surface friction — is met; the friction list
above is the concrete pre-finals fix queue. Numbers are sanity only (small, mixed,
contamination on the public/synthetic sets).

## Phase-35 resolution of the friction list
1. **crypto blind arena — WON'T/CAN'T LOAD.** The NYU bench ships no crypto category
   (categories = forensics/misc/pwn/rev/web); there is no real crypto holdout to load. Crypto
   stays synthetic-only (`eval/make_dev_*`); a real crypto baseline/C1 is not available.
2. **rev holdout — ALREADY KEYED (P34 misdiagnosis).** The real rev holdout is loaded+keyed by
   `eval/real_loader.py`: `arena/real_rev` (rr_*) + `vault/scorer_keys_real` + `manifest_real.json`
   (20 holdout / 9 dev). P34 wrongly used the SYNTHETIC `r7_*`/`scorer_keys_rev` set; a finals/C1
   rev run must use rr_* + scorer_keys_real.
3. reproduce-gate dir path — FIXED (Phase 34), locked by tests/test_p34_fixes.py.
4. pwn per-exp code — FIXED (Phase 34), locked by tests/test_p34_fixes.py.
5. misc `7z` — FIXED: `ctfagent-misc:0.2` (docker/Dockerfile.misc2) adds p7zip (7z/7za); finals
   misc image = 0.2. (0.1 kept for prior-result reproducibility.)
6. Scheduler cid/id — FIXED (Phase 34), locked by tests/test_p34_fixes.py.
7. per-category sequential execution — documented in docs/runbook.md §6.
8. session-orchestrated (competition.py ≠ LLM spawner) — documented in docs/runbook.md intro.
