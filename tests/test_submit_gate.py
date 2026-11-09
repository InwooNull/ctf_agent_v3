"""SubmitGate governance — the Phase-25 top priority, enforced by test.

Proves the four rules that the ACDC quals taught us the hard way:
  1. a SUB-AGENT role can never submit (it holds no client and the call raises);
  2. an UNVERIFIED candidate (no evidence chain) is never submitted;
  3. a DUPLICATE flag / already-solved challenge is blocked (no re-spray);
  4. the per-challenge attempt CAP and the 429 rate-limit BACKOFF hold.
Plus: the append-only log stores only the flag's sha256, never the flag.
"""
import json
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from connector.ctfd_client import RateLimited  # noqa: E402
from connector.submit_gate import (  # noqa: E402
    SubmitGate, NotAuthorized, UnverifiedCandidate, DuplicateSubmission,
    AttemptCapReached,
)
from schemas.records import Candidate  # noqa: E402


class FakeClient:
    """Stand-in CTFd client: scripted statuses, counts POSTs, can raise RateLimited."""
    def __init__(self, script=None, flag_correct=None):
        self.script = list(script or [])     # list of status strings or 'RL' tokens
        self.flag_correct = flag_correct
        self.calls = []

    def submit_flag(self, cid, flag):
        self.calls.append((cid, flag))
        if self.script:
            tok = self.script.pop(0)
            if tok == "RL":
                raise RateLimited("ratelimited")
            return tok, f"msg:{tok}"
        status = "correct" if flag == self.flag_correct else "incorrect"
        return status, status


def _verified(value, refs=("hyp-E0", "obs-1")):
    return Candidate(value=value, confidence=0.9, evidence_refs=list(refs), status="VERIFIED")


def _log_path():
    d = tempfile.mkdtemp()
    return Path(d) / "submissions.jsonl"


class SubAgentCannotSubmit(unittest.TestCase):
    def test_subagent_gate_has_no_client_and_refuses(self):
        gate = SubmitGate.for_subagent(log_path=_log_path())
        self.assertIsNone(gate.client)
        with self.assertRaises(NotAuthorized):
            gate.submit_candidate("14", _verified("acdc2026{x}"))
        with self.assertRaises(NotAuthorized):
            gate.submit_flag_value("14", "acdc2026{x}")

    def test_subagent_can_only_report(self):
        gate = SubmitGate.for_subagent(log_path=_log_path())
        n = gate.report_candidate("14", _verified("acdc2026{a}"))
        self.assertEqual(n, 1)
        self.assertEqual(len(gate.reported("14")), 1)
        # reporting never touches a network client (there is none) and never logs a submit
        self.assertFalse(gate.log_path.exists())


class EvidenceChain(unittest.TestCase):
    def test_unverified_candidate_blocked(self):
        c = FakeClient(flag_correct="acdc2026{real}")
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path())
        unver = Candidate(value="acdc2026{real}", confidence=0.3,
                          evidence_refs=["e"], status="UNVERIFIED")
        with self.assertRaises(UnverifiedCandidate):
            gate.submit_candidate("14", unver)
        self.assertEqual(c.calls, [])  # never reached the network

    def test_verified_but_no_evidence_blocked(self):
        c = FakeClient(flag_correct="acdc2026{real}")
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path())
        no_ev = Candidate(value="acdc2026{real}", confidence=0.9,
                          evidence_refs=[], status="VERIFIED")
        with self.assertRaises(UnverifiedCandidate):
            gate.submit_candidate("14", no_ev)
        self.assertEqual(c.calls, [])

    def test_verified_with_evidence_submits(self):
        c = FakeClient(flag_correct="acdc2026{real}")
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path())
        status, _ = gate.submit_candidate("14", _verified("acdc2026{real}"))
        self.assertEqual(status, "correct")
        self.assertEqual(len(c.calls), 1)


class DuplicateAndCap(unittest.TestCase):
    def test_duplicate_flag_blocked(self):
        c = FakeClient(script=["incorrect"])
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path())
        gate.submit_candidate("14", _verified("acdc2026{wrong}"))
        with self.assertRaises(DuplicateSubmission):
            gate.submit_candidate("14", _verified("acdc2026{wrong}"))
        self.assertEqual(len(c.calls), 1)  # second never hit the network

    def test_already_solved_blocked(self):
        c = FakeClient(script=["correct"])
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path())
        gate.submit_candidate("14", _verified("acdc2026{right}"))
        with self.assertRaises(DuplicateSubmission):
            gate.submit_candidate("14", _verified("acdc2026{other}"))
        self.assertEqual(len(c.calls), 1)

    def test_attempt_cap(self):
        c = FakeClient(script=["incorrect"] * 10)
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path(),
                                           max_attempts_per_challenge=3)
        for i in range(3):
            gate.submit_candidate("14", _verified(f"acdc2026{{w{i}}}"))
        with self.assertRaises(AttemptCapReached):
            gate.submit_candidate("14", _verified("acdc2026{w4}"))
        self.assertEqual(len(c.calls), 3)


class RateLimitBackoff(unittest.TestCase):
    def test_429_backoff_then_success(self):
        slept = []
        c = FakeClient(script=["RL", "RL", "correct"])
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path(),
                                           max_429_retries=4, sleep=slept.append)
        status, _ = gate.submit_candidate("14", _verified("acdc2026{ok}"))
        self.assertEqual(status, "correct")
        self.assertEqual(len(c.calls), 3)          # 2 rate-limited + 1 scored
        self.assertEqual(len(slept), 2)            # backed off twice
        self.assertLessEqual(slept[0], slept[1])   # escalating

    def test_429_exhausted_raises(self):
        c = FakeClient(script=["RL"] * 10)
        gate = SubmitGate.for_orchestrator(c, log_path=_log_path(),
                                           max_429_retries=2, sleep=lambda s: None)
        with self.assertRaises(RateLimited):
            gate.submit_candidate("14", _verified("acdc2026{x}"))
        # a rate-limited POST is NOT a scored attempt, so it never counts toward the cap
        self.assertEqual(gate._scored.get("14", 0), 0)


class LogDiscipline(unittest.TestCase):
    def test_log_is_sha_only_and_append_only(self):
        lp = _log_path()
        c = FakeClient(script=["incorrect", "correct"])
        gate = SubmitGate.for_orchestrator(c, log_path=lp)
        gate.submit_candidate("14", _verified("acdc2026{aaa}"))
        gate.submit_candidate("14", _verified("acdc2026{bbb}"))
        rows = [json.loads(l) for l in lp.read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        blob = lp.read_text()
        self.assertNotIn("acdc2026{aaa}", blob)
        self.assertNotIn("acdc2026{bbb}", blob)
        for r in rows:
            self.assertEqual(len(r["flag_sha256"]), 64)
            self.assertIn("status", r)

    def test_state_rebuilt_from_log_blocks_resubmit_in_fresh_process(self):
        lp = _log_path()
        c1 = FakeClient(script=["correct"])
        SubmitGate.for_orchestrator(c1, log_path=lp).submit_candidate(
            "14", _verified("acdc2026{solved}"))
        # a brand-new gate (fresh process) replays the log and refuses to resubmit
        c2 = FakeClient(script=["correct"])
        gate2 = SubmitGate.for_orchestrator(c2, log_path=lp)
        with self.assertRaises(DuplicateSubmission):
            gate2.submit_candidate("14", _verified("acdc2026{anything}"))
        self.assertEqual(c2.calls, [])


if __name__ == "__main__":
    unittest.main()
