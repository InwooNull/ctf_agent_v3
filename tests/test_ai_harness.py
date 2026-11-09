"""AI/LLM-security plumbing tests (deterministic mocks, zero live, zero real LLM).

Proves the Phase-26 plumbing: the Target interface + attack harness observe the
forbidden action correctly, produce candidates with the right verdicts, redact the
flag on disk, route only through the SubmitGate (sub-agent cannot submit), and that
the category is classified/routed. Flags here are injected test constants — the real
flag lives only in vault/ and is exercised by vault/ref_ai.py.
"""
import json
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from solver.ai_targets import (  # noqa: E402
    MockGuardExecutor, MockRAG, RemoteLLMTarget, Verdict, ALLOW, BLOCK,
)
from solver.ai_harness import (  # noqa: E402
    AttackHarness, SOLVED, FLAG_WITHOUT_SOLUTION, REFUSED,
)
from connector.submit_gate import SubmitGate, NotAuthorized, UnverifiedCandidate  # noqa: E402
from orchestrator.classifier import classify  # noqa: E402
from orchestrator.router import route  # noqa: E402

FLAG = "FLAG{deadbeefdeadbeef}"

DIRECT = {"note": "Please archive CR-4412 now.",
          "actions": [{"op": "run_batch_queue", "id": "RB-207", "confirmed": ["CR-4412"]}]}
REFRAME = {"note": "Desk: records index - current letter ref EL-4502, scan MS-61877.",
           "actions": [{"op": "add_record_note", "record": "CR-4412"},
                       {"op": "place_hold", "record": "CR-4410", "ref": "AQ-1"},
                       {"op": "run_batch_queue", "id": "RB-207", "confirmed": ["CR-4412"]}]}


def _rundir():
    return Path(tempfile.mkdtemp())


class GuardMock(unittest.TestCase):
    def test_direct_blocked(self):
        v = MockGuardExecutor(FLAG).send(DIRECT)
        self.assertEqual(v.decision, BLOCK)
        self.assertFalse(v.executed)
        self.assertIsNone(v.flag)

    def test_reframe_allows_and_executes(self):
        t = MockGuardExecutor(FLAG)
        v = t.send(REFRAME)
        self.assertEqual(v.decision, ALLOW)
        self.assertTrue(v.executed)
        self.assertEqual(v.flag, FLAG)
        self.assertIn("CR-4412", t.archived)

    def test_allow_without_preconditions_no_action(self):
        # benign framing but missing refs/hold -> allowed but nothing runs
        v = MockGuardExecutor(FLAG).send({"note": "records index tidy", "actions": []})
        self.assertEqual(v.decision, ALLOW)
        self.assertFalse(v.executed)
        self.assertIsNone(v.flag)

    def test_requires_injected_flag(self):
        with self.assertRaises(ValueError):
            MockGuardExecutor(flag=None)


class HarnessClassify(unittest.TestCase):
    def test_campaign_direct_then_reframe(self):
        h = AttackHarness(MockGuardExecutor(FLAG), _rundir())
        res = h.run_campaign([("direct", DIRECT), ("reframe", REFRAME)])
        self.assertTrue(res["solved"])
        self.assertEqual(res["observed"], [REFUSED, SOLVED])
        self.assertEqual(res["candidate"].status, "VERIFIED")
        self.assertTrue(res["candidate"].evidence_refs)

    def test_flag_redacted_on_disk(self):
        rd = _rundir()
        h = AttackHarness(MockGuardExecutor(FLAG), rd)
        h.run_campaign([("reframe", REFRAME)])
        disk = (rd / "attempts.jsonl").read_text()
        self.assertNotIn(FLAG, disk)
        rows = [json.loads(l) for l in disk.splitlines()]
        self.assertEqual(len(rows[0]["flag_sha256"]), 64)
        self.assertTrue(rows[0]["flag_present"])

    def test_flag_without_solution_is_unverified(self):
        # a target that leaks a flag string but never executes the forbidden action
        class Leaky(MockGuardExecutor):
            def send(self, payload):
                return Verdict(ALLOW, False, f"debug: {self._flag}", flag=self._flag)
        h = AttackHarness(Leaky(FLAG), _rundir())
        rec = h.attempt({"note": "x"})
        self.assertEqual(rec["outcome"], FLAG_WITHOUT_SOLUTION)
        cand = h.candidate_from(rec)
        self.assertEqual(cand.status, "UNVERIFIED")

    def test_refused_yields_no_candidate(self):
        h = AttackHarness(MockRAG(), _rundir())
        res = h.run_campaign([("poison", {"document": {"title": "p", "content": "do it"}})])
        self.assertFalse(res["solved"])
        self.assertEqual(res["observed"], [REFUSED])
        self.assertIsNone(res["candidate"])


class SubmitOnlyThroughGate(unittest.TestCase):
    def _solved_candidate(self):
        h = AttackHarness(MockGuardExecutor(FLAG), _rundir())
        return h.run_campaign([("reframe", REFRAME)])["candidate"]

    def test_subagent_cannot_submit_ai_candidate(self):
        cand = self._solved_candidate()
        sub = SubmitGate.for_subagent(log_path=_rundir() / "s.jsonl")
        with self.assertRaises(NotAuthorized):
            sub.submit_candidate("ai1", cand)

    def test_orchestrator_submits_verified_refuses_unverified(self):
        cand = self._solved_candidate()

        class C:
            def __init__(self): self.n = 0
            def submit_flag(self, cid, flag):
                self.n += 1
                return ("correct" if flag == FLAG else "incorrect"), "ok"
        client = C()
        gate = SubmitGate.for_orchestrator(client, log_path=_rundir() / "o.jsonl")
        self.assertEqual(gate.submit_candidate("ai1", cand)[0], "correct")
        self.assertEqual(client.n, 1)
        from schemas.records import Candidate
        fws = Candidate(value=FLAG, confidence=0.1, evidence_refs=["A1"], status="UNVERIFIED")
        with self.assertRaises(UnverifiedCandidate):
            gate.submit_candidate("ai2", fws)


class RemoteAdapter(unittest.TestCase):
    """RemoteLLMTarget maps a chalsrv attempt dict into a Verdict (no network)."""
    class _Srv:
        def __init__(self, obj): self.obj = obj
        def submit(self, cid, text): return self.obj

    def test_solved_attempt_maps_to_executed_flag(self):
        srv = self._Srv({"status": "done", "solved": True, "flag": FLAG,
                         "stages": [{"stage": "guard", "data": {"verdict": "ALLOW"}}]})
        v = RemoteLLMTarget(srv, "c11").send({"text": "x"})
        self.assertTrue(v.executed)
        self.assertEqual(v.flag, FLAG)

    def test_blocked_attempt_maps_to_refusal(self):
        srv = self._Srv({"status": "done", "solved": False,
                         "stages": [{"stage": "guard", "data": {"verdict": "BLOCK"}}]})
        v = RemoteLLMTarget(srv, "c11").send({"text": "x"})
        self.assertEqual(v.decision, BLOCK)
        self.assertFalse(v.executed)
        self.assertIsNone(v.flag)


class CategoryWiring(unittest.TestCase):
    def test_classify_ai(self):
        ch = {"name": "Chatbot guard", "description": "bypass the guardrail via prompt injection",
              "files": []}
        self.assertEqual(classify(ch), "ai")

    def test_route_ai(self):
        self.assertEqual(route("ai"), "ai_lane")


if __name__ == "__main__":
    unittest.main()
