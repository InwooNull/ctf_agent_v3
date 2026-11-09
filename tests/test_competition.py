"""End-to-end integration: the whole agent on a deterministic mock competition.

Proves all Phase-29 policies fire together in one run (orchestrator.competition):
fetch -> classify/route -> flags-per-hour scheduling -> per-challenge stop-loss ->
candidate -> triage first-pass/decoy -> reproduce-before-submit SubmitGate -> submit,
against connector.mock_ctfd. No live, no LLM; flags live only in the mock + fixture.
"""
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from connector.ctfd_client import CTFdClient                 # noqa: E402
from connector.mock_ctfd import MockCTFd, VALID_USER         # noqa: E402
from connector.submit_gate import SubmitGate, NotAuthorized  # noqa: E402
from orchestrator.competition import Competition             # noqa: E402
from schemas.records import Candidate                        # noqa: E402

# ctfd_id -> role
ROLES = {1: "easy", 2: "normal", 3: "no_progress", 4: "decoy", 5: "repro_fail", 6: "near_miss"}
FLAGS = {1: "acdc2026{easy1win}", 2: "acdc2026{normalwin}", 3: "acdc2026{neverfound}",
         4: "acdc2026{realdecoychal}", 5: "acdc2026{reprofail}", 6: "acdc2026{nearmiss}"}
DECOY_VALUE = "acdc2026{this_is_a_sample_flag}"

# score / difficulty / est_cost drive the scheduler priority (expected order below)
SCRIPT = {
    "live_1": {"score": 100, "difficulty": "easy", "est_cost": 1.0},  # pri 100
    "live_2": {"score": 80, "difficulty": "easy", "est_cost": 1.0},   # pri 80
    "live_6": {"score": 120, "difficulty": "med", "est_cost": 1.0},   # pri 60
    "live_5": {"score": 100, "difficulty": "med", "est_cost": 1.0},   # pri 50
    "live_4": {"score": 60, "difficulty": "med", "est_cost": 1.0},    # pri 30
    "live_3": {"score": 100, "difficulty": "hard", "est_cost": 1.0},  # pri 25
}
EXPECTED_ORDER = ["live_1", "live_2", "live_6", "live_5", "live_4", "live_3"]

DESCRIPTIONS = {1: "recover the RSA modulus", 2: "XSS in the cookie handler",
                3: "crackme, decompile the binary", 4: "forensics misc challenge",
                5: "prompt injection jailbreak the llm", 6: "heap overflow libc pwn"}


def _V(value, refs):
    return Candidate(value=value, confidence=0.9, evidence_refs=list(refs), status="VERIFIED")


def solver(cid, idx, info):
    ctfd = int(str(cid).split("_")[-1])
    role, flag = ROLES[ctfd], FLAGS[ctfd]
    if role == "normal":
        return {"info_gain": 1} if idx == 0 else {"info_gain": 1, "candidate": _V(flag, [f"e{idx}"])}
    if role == "repro_fail":
        return {"info_gain": 1} if idx == 0 else {"info_gain": 1, "candidate": _V(flag, [f"e{idx}"])}
    if role == "decoy":
        return {"info_gain": 0, "candidate": _V(DECOY_VALUE, ["e0"])} if idx == 0 else {"info_gain": 0}
    if role == "near_miss":
        if idx < 3:
            return {"info_gain": 0, "verified_chain": idx >= 1}
        return {"info_gain": 0, "verified_chain": True, "candidate": _V(flag, [f"e{idx}"])}
    return {"info_gain": 0}  # no_progress / easy (easy solved by first_pass)


def reproducer(cid, candidate):
    ctfd = int(str(cid).split("_")[-1])
    if ROLES[ctfd] == "repro_fail":
        return {"ok": False, "flag": None}
    return {"ok": True, "flag": candidate.value}


def _mock():
    challenges = [{"id": i, "name": f"chal{i}", "category": "misc", "value": 100,
                   "solved_by_me": False, "description": DESCRIPTIONS[i]} for i in ROLES]
    files = {"1/flag.txt": FLAGS[1].encode(),
             "4/readme.txt": f"example output: {DECOY_VALUE}".encode()}
    return MockCTFd(flags=FLAGS, challenges=challenges, files=files)


def _client(srv):
    return CTFdClient(srv.base_url, name=VALID_USER["name"],
                      password=VALID_USER["password"], sleep=lambda s: None)


class EndToEnd(unittest.TestCase):
    def test_full_run_all_policies_fire(self):
        with _mock() as srv:
            store = Path(tempfile.mkdtemp())
            comp = Competition(_client(srv), Path(tempfile.mkdtemp()), store, solver,
                               reproducer, SCRIPT, challenge_caps={"experiments": 3})
            out = comp.run()

        outcomes = {t["cid"]: t["outcome"] for t in out["trace"]}
        # scheduler processed in expected flags-per-hour priority order
        self.assertEqual([t["cid"] for t in out["trace"]], EXPECTED_ORDER)
        # easy (first-pass), normal, near-miss solved; the rest blocked/stopped
        self.assertEqual(outcomes["live_1"], "solved")   # exposed flag.txt via first_pass
        self.assertEqual(outcomes["live_2"], "solved")   # scripted + reproduce ok
        self.assertEqual(outcomes["live_6"], "solved")   # near-miss raised budget once
        self.assertEqual(outcomes["live_3"], "stopped")  # stop-loss, no progress
        self.assertEqual(outcomes["live_4"], "stopped")  # decoy rejected -> never solved
        self.assertEqual(outcomes["live_5"], "stopped")  # reproduction failed -> never submitted

        evs = "\n".join(out["events"])
        self.assertIn("first_pass solved", evs)
        self.assertIn("decoy", evs)
        self.assertIn("repro_fail", evs)
        self.assertIn("near-miss: budget raised once", evs)
        self.assertIn("no progress, giving up", evs)

        # only the 3 real solves reached the mock platform (decoy/repro-fail blocked pre-network)
        scored = [(cid, sub) for cid, sub in srv.state.attempts]
        self.assertEqual(sorted(c for c, _ in scored), [1, 2, 6])
        self.assertNotIn(DECOY_VALUE, [s for _, s in scored])

    def test_global_budget_cap_halts(self):
        with _mock() as srv:
            comp = Competition(_client(srv), Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp()),
                               solver, reproducer, SCRIPT,
                               global_caps={"experiments": 2}, challenge_caps={"experiments": 3})
            out = comp.run()
        # the global cap stops the queue before every challenge is attempted
        self.assertLess(len(out["trace"]), len(ROLES))
        self.assertTrue(out["remaining"])
        self.assertTrue(any("global budget spent" in e for e in out["events"]))

    def test_checkpoint_resume_no_double_submit(self):
        arena = Path(tempfile.mkdtemp())
        store = Path(tempfile.mkdtemp())
        with _mock() as srv:
            # first leg: stop after 2 challenges
            Competition(_client(srv), arena, store, solver, reproducer, SCRIPT,
                        challenge_caps={"experiments": 3}).run(max_challenges=2)
            attempts_after_leg1 = list(srv.state.attempts)
            self.assertEqual(sorted(c for c, _ in attempts_after_leg1), [1, 2])
            # resume: a fresh Competition over the same store finishes the rest
            out = Competition(_client(srv), arena, store, solver, reproducer, SCRIPT,
                              challenge_caps={"experiments": 3}).run()
        self.assertEqual(len(out["done"]), len(ROLES))
        # live_1 / live_2 were already solved -> not submitted again (idempotent)
        solved_submits = [c for c, _ in srv.state.attempts]
        self.assertEqual(solved_submits.count(1), 1)
        self.assertEqual(solved_submits.count(2), 1)

    def test_subagent_cannot_submit_in_pipeline(self):
        # the gate the competition builds is orchestrator-role; a sub-agent gate can't submit
        sub = SubmitGate.for_subagent(log_path=Path(tempfile.mkdtemp()) / "s.jsonl",
                                      reproducer=reproducer)
        with self.assertRaises(NotAuthorized):
            sub.submit_candidate("live_2", _V(FLAGS[2], ["e1"]))


if __name__ == "__main__":
    unittest.main()
