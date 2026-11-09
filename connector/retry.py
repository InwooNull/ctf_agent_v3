"""Shared resilience utilities for the live connectors (stdlib only).

Phase 25 consolidation: the ad-hoc backoff loops that grew inside chalsrv.py and
ctfd_client.py during the ACDC quals are pulled out here so both the CTFd client
and the challenge-server clients share one, tested implementation.

Three failure shapes were observed live and are handled here:

  429 rate limit        consecutive 429s escalate the wait (15 -> 30 -> 45 -> 70s,
                        clamped), honoring any server `retry_after` that is larger,
                        plus a fixed `settle` to clear a short rate window.
  model system_error    the challenge-server returns status "system_error"/"provider_failed"
                        with empty stages ~half the time; wait a flat `system_error_gap`
                        (32s) and retry the *same* request.
  network/DNS blip      a transient getaddrinfo failure (EAI_AGAIN) or connection
                        reset is retried a few times with a short linear backoff;
                        `is_transient_network_error()` classifies them so a caller
                        can also persist context and resume (see note below).

None of these helpers perform I/O themselves; they only compute delays and classify
errors, and they call an injectable `sleep`/`clock` so tests run instantly.

Context-preserving resume: `is_transient_network_error()` lets a long-running driver
distinguish a recoverable blip (retry / resume from the last checkpoint) from a hard
error (abort). The supervisor's checkpoint machinery is what actually resumes; this
module only gives the classification hook.
"""
import time

# default schedules (seconds) — the values tuned live during ACDC quals
RATE_LIMIT_SCHEDULE = (15, 30, 45, 70)   # escalating floor per consecutive 429
RATE_LIMIT_SETTLE = 18                    # fixed pre-POST settle to clear a short window
SYSTEM_ERROR_GAP = 32                     # flat wait to ride out provider_failed outages
NETWORK_RETRIES = 3                       # transient-network retry attempts
NETWORK_BACKOFF = 1.5                     # linear base for network retries

# substrings that mark a *transient* (retryable) network/DNS failure
_TRANSIENT_MARKERS = (
    "eai_again",                 # getaddrinfo: temporary failure in name resolution
    "temporary failure in name resolution",
    "name or service not known",
    "connection reset",
    "connection refused",
    "connection timed out",
    "timed out",
    "broken pipe",
    "network is unreachable",
    "no route to host",
)


def rate_limit_backoff(consecutive_429, server_retry_after=None,
                       schedule=RATE_LIMIT_SCHEDULE, settle=RATE_LIMIT_SETTLE):
    """Seconds to wait after the Nth consecutive 429 (consecutive_429 is 1-based).

    Returns a floor from the escalating schedule (last value repeats once past the
    end), never less than the server's own retry_after + a small margin, plus the
    fixed settle so the next POST lands outside a short rate window.
    """
    if consecutive_429 < 1:
        consecutive_429 = 1
    idx = min(consecutive_429, len(schedule)) - 1
    floor = schedule[idx]
    if server_retry_after:
        try:
            floor = max(floor, int(server_retry_after) + 3)
        except (TypeError, ValueError):
            pass
    return floor + settle


def is_transient_network_error(exc_or_msg):
    """True if the exception/message looks like a recoverable network/DNS blip.

    Accepts an Exception or a string. Matching is substring, case-insensitive, so it
    catches urllib.error.URLError("<urlopen error [Errno -3] Temporary failure ...>")
    and the bare "EAI_AGAIN" the challenge-server client surfaces.
    """
    msg = str(getattr(exc_or_msg, "reason", exc_or_msg) or "")
    msg2 = str(exc_or_msg or "")
    hay = (msg + " " + msg2).lower()
    return any(m in hay for m in _TRANSIENT_MARKERS)


def network_backoff(attempt, base=NETWORK_BACKOFF):
    """Linear backoff for the Nth (1-based) network retry attempt."""
    if attempt < 1:
        attempt = 1
    return base * attempt


def retry_network(fn, retries=NETWORK_RETRIES, base=NETWORK_BACKOFF,
                  sleep=time.sleep, is_transient=is_transient_network_error):
    """Call fn(); on a *transient* network error retry up to `retries` times with
    linear backoff, re-raising the last error if all attempts fail. A non-transient
    error (HTTP 4xx/5xx raised as something else, programming error) is re-raised
    immediately — we only swallow blips.
    """
    last = None
    for attempt in range(retries + 1):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - classify, then re-raise if hard
            if not is_transient(e):
                raise
            last = e
            if attempt >= retries:
                raise
            sleep(network_backoff(attempt + 1, base))
    raise last  # pragma: no cover - loop always returns or raises above


class Backoff:
    """Stateful backoff tracker for a single request loop (one challenge/attempt).

    Tracks consecutive-429 escalation across the loop and exposes one sleep() the
    caller invokes with the observed outcome. Injectable sleep/clock keep it testable.
    Not thread-safe (each in-flight request owns its own Backoff).
    """

    def __init__(self, schedule=RATE_LIMIT_SCHEDULE, settle=RATE_LIMIT_SETTLE,
                 system_error_gap=SYSTEM_ERROR_GAP, sleep=time.sleep):
        self.schedule = schedule
        self.settle = settle
        self.system_error_gap = system_error_gap
        self._sleep = sleep
        self.consecutive_429 = 0
        self.slept_total = 0.0

    def _do(self, secs):
        self.slept_total += secs
        self._sleep(secs)
        return secs

    def on_rate_limited(self, server_retry_after=None):
        self.consecutive_429 += 1
        secs = rate_limit_backoff(self.consecutive_429, server_retry_after,
                                  self.schedule, settle=0)  # settle added separately below
        return self._do(secs)

    def on_system_error(self):
        self.consecutive_429 = 0
        return self._do(self.system_error_gap)

    def on_success(self):
        """Reset the 429 escalation after a non-rate-limited outcome."""
        self.consecutive_429 = 0

    def settle_wait(self):
        """The fixed pre-POST settle (clears a short rate window)."""
        if self.settle:
            return self._do(self.settle)
        return 0.0
