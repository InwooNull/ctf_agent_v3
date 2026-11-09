"""Phase CM: the mode switch for the shared core — ONE system, TWO modes.

The whole agent (triage/router, category harnesses, ctfagent-* images, skill_pack,
StopLoss, verifier/evidence capture, checkpoint/resume, writeup log) is shared. Only
a thin *policy profile* differs by mode, and that profile is declared HERE so every
consumer reads one source of truth:

  - contest (DEFAULT): a live competition. Network to the CHALLENGE TARGET is allowed
      (remote pwn `nc`, live web); no vault — a candidate is verified by the server or
      the flag format; the goal is to MAXIMISE solves inside a budget.
  - bench (explicit, --bench only): the honest blind measurement. `--network none`,
      the blind vault + scorer key, goal = honest measurement. This is the EXISTING
      behaviour and must stay byte-identical; nothing here changes it.

CM1 only *declares* the switch and threads a `mode` value through the shared core.
The behavioural consequences are wired in later phases, each reading these profiles:
  network policy -> CM2, operational discipline -> CM3, evidence/writeup/submit -> CM4.

Stdlib-only, no I/O, no side effects — safe to import anywhere.
"""

CONTEST = "contest"
BENCH = "bench"
DEFAULT = CONTEST
VALID = (CONTEST, BENCH)

# Declarative policy per mode. Keys are stable contracts consumed by later CM phases;
# CM1 does not act on them, it only records the chosen mode and surfaces its profile.
PROFILES = {
    CONTEST: {
        "mode": CONTEST,
        "network": "target-only",          # CM2: egress allowed ONLY to challenge target
        "use_vault": False,                # verify via server / flag-format, not a vault
        "verify": "server-or-format",
        "auto_submit": False,              # CM4: never auto-submit; surface candidate to user
        "rate_limited": True,              # CM2: no brute/repeat spray at contest servers
        "experience_tag": "contest",       # CM4: keep contest learning off the blind bench
        "goal": "maximize-solves-in-budget",
    },
    BENCH: {
        "mode": BENCH,
        "network": "none",                 # UNCHANGED: --network none blind isolation
        "use_vault": True,                 # blind vault + scorer key
        "verify": "vault",
        "auto_submit": False,
        "rate_limited": False,
        "experience_tag": "bench",         # blind measurement, kept uncontaminated
        "goal": "honest-measurement",
    },
}


def normalize(mode):
    """Return a canonical mode string. None -> DEFAULT (contest). Raises on garbage."""
    if mode is None:
        return DEFAULT
    m = str(mode).strip().lower()
    if m not in VALID:
        raise ValueError(f"unknown mode {mode!r}; valid: {VALID}")
    return m


def is_bench(mode):
    return normalize(mode) == BENCH


def profile(mode):
    """A COPY of the policy profile for `mode` (so callers can't mutate the table)."""
    return dict(PROFILES[normalize(mode)])
