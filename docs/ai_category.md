# AI / LLM security category

ACDC 2026's real target surface was AI/LLM security, and our only quals flag
(Semantic Collision) was a guard bypass. This is the category for that terrain. The
target under test is an **LLM system** (guard + executor, a RAG pipeline, an agent
chain). Real challenges are remote LLM services attacked over HTTP (`connector/chalsrv.py`);
offline we prove the plumbing against deterministic **rule-based mocks** — no real
model, no tokens, no network.

**Scope / ethics.** Targets are *authorized* competition/CTF challenge servers or local
mocks only. This is not a general prompt-injection tool against third-party production
LLMs, and we do not connect to live competition infrastructure (quals are over).

## Success = observing the forbidden action

Every subtype defines a **forbidden action** the target must not be made to perform.
Success is **observing that action actually execute** (and the flag emitted) — never a
flag-shaped string on its own, never a guess. This mirrors the verifier's SOLVED rule
and the SubmitGate evidence chain:

| observation | outcome | candidate |
|---|---|---|
| forbidden action executed + flag emitted | `SOLVED` | VERIFIED (submittable) |
| flag-shaped string, action did **not** run | `FLAG_WITHOUT_SOLUTION` | UNVERIFIED (refused) |
| guard BLOCK / grounded refusal | `REFUSED` | none |

## Subtypes

- **guard-bypass** — a guard (classifier/policy) gates an executor; make the guard
  ALLOW a request that drives a forbidden action (e.g. archive a protected record).
  *Forbidden action: the gated operation runs.* (ACDC Semantic Collision.)
- **rag-poisoning** — poison the retrieved context so the model releases a
  restricted record. *Forbidden action: the restricted release.* (Grounded models
  refuse participant docs — often a wall.)
- **agent-chain-injection** — inject through a multi-stage pipeline
  (research → analysis → execution) so a later stage runs a classified op.
  *Forbidden action: the classified op executes.*
- **direct-prompt-injection** — override the system prompt/instructions directly to
  make the model do the prohibited thing. *Forbidden action: the prohibited output/call.*
- **memory-poisoning** — plant content in session/agent memory that a later session
  acts on without the original guard/registry. *Forbidden action: the later action.*

## Pipeline (same shape as the other categories)

- **Target interface** (`solver/ai_targets.py`): `send(payload) -> Verdict{decision,
  executed, output, flag}`. `LocalMockTarget` subclasses (deterministic) and
  `RemoteLLMTarget` (wraps `chalsrv`) share it.
- **Harness** (`solver/ai_harness.py`): payload → send → observe → record (append-only
  JSONL, flag redacted to sha256), campaign until the forbidden action is observed,
  then a Candidate with the attempt as evidence.
- **Mocks**: `MockGuardExecutor` (direct wording BLOCK, benign "records index tidy"
  reframing ALLOW → archive → flag) and `MockRAG` (grounded refusal, negative case).
  Flags are injected from `vault/` (`vault/gen_ai.py` → `vault/ai_flags.json`), never
  hard-coded and never solver-visible.
- **Submission**: candidates go through the Phase-25 `SubmitGate`. Sub-agents report
  only; the orchestrator submits VERIFIED candidates. Unverified/FWS are refused.
- **Reference proof**: `vault/ref_ai.py` (non-LLM, deterministic, offline) runs the
  reframing exploit to a verified flag, confirms the RAG refusal, and exercises the
  gate. `python3 vault/ref_ai.py` → `PROOF ai-plumbing OK`.
- **Experience seed**: `store/experience_ai.jsonl` stores verified attack patterns
  (subtype, evasion pattern, recipe, confidence) — never flags — for later reuse (C2).
