"""Resilience library (connector/retry.py) + chalsrv single-in-flight discipline.

Covers: the escalating 429 backoff schedule, transient-network classification, the
retry_network helper, and — the live bug this phase fixes — that AttemptServer.submit
issues exactly ONE POST per real attempt (polls the result by id, never re-POSTs),
while still retrying 429 / system_error / network blips that created no attempt.
"""
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from connector import retry  # noqa: E402
from connector.chalsrv import AttemptServer  # noqa: E402


class RateLimitSchedule(unittest.TestCase):
    def test_escalation(self):
        waits = [retry.rate_limit_backoff(n, settle=0) for n in (1, 2, 3, 4, 5, 6)]
        # schedule 15,30,45,70 then clamps at 70; monotonic non-decreasing
        self.assertEqual(waits[:4], [15, 30, 45, 70])
        self.assertEqual(waits[4], 70)
        self.assertEqual(waits[5], 70)
        self.assertEqual(waits, sorted(waits))

    def test_settle_added(self):
        self.assertEqual(retry.rate_limit_backoff(1, settle=18), 15 + 18)

    def test_server_retry_after_honored_when_larger(self):
        self.assertEqual(retry.rate_limit_backoff(1, server_retry_after=100, settle=0), 103)
        # smaller server hint does not shrink our floor
        self.assertEqual(retry.rate_limit_backoff(2, server_retry_after=1, settle=0), 30)


class TransientClassify(unittest.TestCase):
    def test_transient(self):
        for m in ("EAI_AGAIN", "Temporary failure in name resolution",
                  "[Errno 104] Connection reset by peer", "timed out"):
            self.assertTrue(retry.is_transient_network_error(m), m)

    def test_not_transient(self):
        for m in ("HTTP 403 forbidden", "success=false", "bad flag", ""):
            self.assertFalse(retry.is_transient_network_error(m), m)

    def test_retry_network_retries_then_succeeds(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("EAI_AGAIN temporary failure")
            return "ok"
        out = retry.retry_network(flaky, retries=5, sleep=lambda s: None)
        self.assertEqual(out, "ok")
        self.assertEqual(calls["n"], 3)

    def test_retry_network_reraises_hard_error(self):
        def hard():
            raise ValueError("not a network thing")
        with self.assertRaises(ValueError):
            retry.retry_network(hard, sleep=lambda s: None)


class Backoff(unittest.TestCase):
    def test_backoff_escalates_and_resets(self):
        slept = []
        b = retry.Backoff(settle=0, sleep=slept.append)
        b.on_rate_limited()
        b.on_rate_limited()
        self.assertEqual(slept, [15, 30])
        b.on_success()
        self.assertEqual(b.consecutive_429, 0)
        b.on_rate_limited()
        self.assertEqual(slept[-1], 15)  # reset -> back to the first rung


class _FakeAttemptServer(AttemptServer):
    """AttemptServer with scripted HTTP; counts POSTs to prove single in-flight."""
    def __init__(self, post_script, attempt_states):
        super().__init__("http://x", token="t", sleep=lambda s: None, verbose=False)
        self.post_script = list(post_script)   # responses for each POST (s, body-dict)
        self.attempt_states = list(attempt_states)  # successive get_attempt returns
        self.posts = 0
        self.idle = True

    def list_attempts(self, cid):
        return []  # always idle for the test

    def get_attempt(self, attempt_id, to=60):
        if self.attempt_states:
            return self.attempt_states.pop(0)
        return {"status": "solved", "solved": True}

    def _http(self, method, path, body=None, to=300):
        if method == "POST":
            self.posts += 1
            import json
            s, obj = self.post_script.pop(0)
            return s, json.dumps(obj)
        return 404, "{}"


class SingleInFlight(unittest.TestCase):
    def test_running_attempt_is_polled_not_reposted(self):
        # POST once -> running; then poll: running, then solved. Exactly ONE POST.
        srv = _FakeAttemptServer(
            post_script=[(200, {"status": "running", "attempt_id": "a1"})],
            attempt_states=[{"status": "running"}, {"status": "solved", "solved": True}],
        )
        out = srv.submit("c11", "hello", retries=5)
        self.assertEqual(out.get("solved"), True)
        self.assertEqual(srv.posts, 1)   # never re-POSTed the in-flight attempt

    def test_system_error_retries_with_fresh_post(self):
        # system_error creates no attempt, so a second POST is correct, not a dup.
        srv = _FakeAttemptServer(
            post_script=[(200, {"status": "system_error", "stages": []}),
                         (200, {"status": "solved", "solved": True})],
            attempt_states=[],
        )
        out = srv.submit("c11", "hi", retries=5)
        self.assertEqual(out.get("solved"), True)
        self.assertEqual(srv.posts, 2)

    def test_429_then_success_single_scored_post(self):
        srv = _FakeAttemptServer(
            post_script=[(429, {"error": {"retry_after_seconds": 5}}),
                         (200, {"status": "done", "solved": True})],
            attempt_states=[],
        )
        out = srv.submit("c11", "hi", retries=5)
        self.assertEqual(out.get("solved"), True)
        self.assertEqual(srv.posts, 2)  # one rejected 429 + one scored


if __name__ == "__main__":
    unittest.main()
