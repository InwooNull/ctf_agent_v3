# Orchestrator policy: budget / stop-loss, reallocation, decoy, reproduce-before-submit

Phase 29 adds four cross-category policies at the orchestrator layer, so effort is
bounded, give-up is timed, the queue is worked best-first, and no decoy or unreproduced
guess is ever submitted. All deterministic and unit-tested; they compose with the
existing SubmitGate / isolation / blind discipline.

## 1. Per-challenge budget + stop-loss — `orchestrator/stoploss.py`
`StopLoss(caps={experiments, wall_s, tokens}, no_progress_k, raise_factor)`.
- `record_round(info_gain, experiments, wall_s, tokens)` logs a round.
- `decide(has_verified_chain)` → `CONTINUE` / `RAISE_ONCE` / `STOP`.
  Fires on budget-spent or K trailing zero-gain rounds. **Near-miss recovery**: if a
  verified exploit chain is held and we have not raised yet, the caps are raised once
  and the stall window reset (so the raise buys real rounds); a second stall → `STOP`.
- `to_dict()/from_dict()` ride in the run checkpoint (resume-safe).

## 2. Inter-challenge reallocation — `orchestrator/scheduler.py`
`Scheduler(challenges=[{id, score, difficulty, est_cost}], global_caps={time_s, experiments})`.
- `priority = (score / difficulty_weight[easy=1,med=2,hard=4]) / est_cost`.
- `next()` returns the best pending challenge while the global cap has room, skipping
  finished ones; `order_of_attempt()` is the deterministic full order (ties → queue order).
- `mark_done`, `record_spend`, `update_difficulty(cid, 'harder'|'easier')` feed progress
  back so a stalled challenge loses priority if revisited.

## 3. Decoy / obvious first pass — `orchestrator/triage.py`
- `is_decoy(value, evidence_refs)` rejects placeholder/sample markers
  (`THIS IS A SAMPLE FLAG`, `changeme`, …) and any format-only value with no evidence.
- `first_pass(challenge_dir)` cheaply scans public files for an exposed flag
  (`flag.txt`, `.env`, hard-coded) and returns labelled hits. Public files only — never
  vault or scorer keys. Found values are still gated below.

## 4. Reproduce-before-submit — `connector/submit_gate.py` (additive)
`SubmitGate(..., decoy_check=None, reproducer=None)` (both opt-in; off ⇒ prior behavior).
On `submit_candidate`, after the evidence chain:
- `decoy_check(value, evidence_refs)` true ⇒ `DecoyRejected` (before any network call);
- `reproducer(cid, candidate)` must return `{ok: True, flag: <same value>}` — a clean,
  history-free re-derivation — else `ReproductionFailed`. Verifier ≠ finder: a candidate
  is only submitted if an independent reproduction re-derives the exact flag.
Sub-agents still cannot submit even with gates wired in (role check is first).

Integration: these are the authoritative policy objects; wiring them into
`Supervisor.run` (consult `StopLoss` per round, drive the queue with `Scheduler`, pass
`decoy_check`/`reproducer` into the gate) is the next step and does not change this logic.
