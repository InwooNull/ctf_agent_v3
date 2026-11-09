# Connector (live platform I/O)

Stdlib-only I/O layer between a live CTFd-style platform (the ACDC 2026 qualifier)
and the offline solver pipelines. It **moves data and submits flags; it never solves
anything**. Clean-room: built during the ACDC quals, consolidated in Phase 25. No
secrets are hardcoded — all credentials come from `config/acdc.env` (chmod 600,
git-ignored) via `load_env()` / `CTFdClient.from_env()`.

## Modules

| file | role |
|------|------|
| `ctfd_client.py` | main CTFd HTTP client: session-cookie auth, list/get/download/submit. |
| `fetch.py`       | pull challenges → `arena/live/<cid>/{challenge.json, files…}` + `store/live/manifest.json`. |
| `submit.py`      | human-operator CLI; thin wrapper over `SubmitGate` (one governance path). |
| `submit_gate.py` | **governance chokepoint** for all submission (role / evidence / dup / cap / backoff / log). |
| `chalsrv.py`     | clients for the per-challenge instance servers (AI-injection challenges). |
| `retry.py`       | shared resilience: 429 escalation, system_error gap, transient-network classify. |
| `mock_ctfd.py`   | stdlib loopback mock of the CTFd backend, for offline tests only (not runtime). |

## Auth (the live gotcha)

The platform is **session-cookie** based, not token based:

    POST /api/v2/auth/login {name, password}   -> Set-Cookie: session=…
    GET  /api/v2/auth/check/cookie             -> {authenticated, user}

State-changing calls (`POST /api/v2/challenges/attempt`) additionally enforce
**same-origin**: without `Origin` + `Referer` matching the host the server returns
`403 "request origin or CSRF token incorrect"`. `CTFdClient` always sends both and
drives a `http.cookiejar.CookieJar`. If the session is closed mid-run, a 401 triggers
**one re-login** and the same request resumes (the c14 lesson).

The per-challenge instance servers (`chalsrv.py`) are different: they use the CTFd
token as a **Bearer** credential (`ACDC_TOKEN`), not the session cookie.

## Submission governance (`SubmitGate`)

The one outward action is funnelled through `SubmitGate`. Rule, enforced in code:

> **Sub-agents report candidates; only the orchestrator submits.**

- `SubmitGate.for_subagent()` → role `subagent`, **no client** → `submit_*` raises
  `NotAuthorized`; only `report_candidate()` (in-memory, no network) is allowed.
- `SubmitGate.for_orchestrator(client)` → `submit_candidate(cid, candidate)` checks,
  in order: role → evidence chain (`status==VERIFIED` + `evidence_refs`) → dup /
  already-solved → per-challenge attempt cap → POST with 429 backoff → append-only log.
- The manual CLI (`submit.py`) goes through `submit_flag_value()` (same gate, skips
  only the evidence check — the operator asserts it; `--force` overrides dup/solved).
- Log: `store/live/submissions.jsonl`, **sha256 of the flag only**, append-only. Gate
  state is rebuilt from it on construction → crash/restart never double-submits.

## Resilience (`retry.py`)

- 429: `rate_limit_backoff()` → 15→30→45→70 s (clamped), honoring a larger server
  `retry_after`, plus a fixed settle. `Backoff` tracks consecutive-429 escalation.
- `system_error` / `provider_failed`: flat 32 s gap, retry the same request.
- transient network/DNS (EAI_AGAIN, reset, timeout): `is_transient_network_error()`
  + `retry_network()` — retry blips, re-raise hard errors.
- `chalsrv` single-in-flight: `wait_idle → POST once → poll by id`; never re-POST a
  live attempt (that created duplicate attempts in the quals).

## Testing (zero live access)

`tests/test_submit_gate.py`, `tests/test_connector_mock.py`, `tests/test_resilience.py`
drive the real client/gate against `mock_ctfd.MockCTFd` (loopback) and fake clients.
Run: `python3 -m unittest discover -s tests`.
