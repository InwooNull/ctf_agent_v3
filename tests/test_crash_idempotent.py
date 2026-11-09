"""Phase 0 fix #2: crashes between a log append and the state save must not
produce duplicate events/commands after resume.

Each event carries a monotonic seq; state.json records last_committed_seq. On
resume the log is reconciled back to the committed seqs, dropping the tail that
a crash left behind.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.supervisor import Supervisor, load_settings  # noqa: E402
from solver.experiment_log import ExperimentLog  # noqa: E402


def challenge(cid="c1"):
    return {"id": cid, "name": cid, "description": "rsa", "files": [], "scenario": {"hypotheses": [{
        "statement": "h", "priority_band": "high",
        "experiments": [{"tool": "t", "argv": [str(i)], "judgment": "inconclusive"} for i in range(3)],
    }]}}


def read_lines(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines()]


class ReconcileUnitTest(unittest.TestCase):
    def test_reconcile_drops_uncommitted_tail(self):
        with tempfile.TemporaryDirectory() as d:
            log = ExperimentLog(d)
            log.append_event("a")                       # seq 1
            log.append_event("b")                       # seq 2
            committed_events = log.event_seq
            log.run("E1", {"tool": "x", "argv": []}, lambda s: ("ok", "o1"))  # command seq 1
            committed_cmds = log.command_seq
            # simulate a crash tail: more appended, never committed to state
            log.append_event("c")                       # seq 3 (uncommitted)
            log.run("E2", {"tool": "y", "argv": []}, lambda s: ("ok", "o2"))  # command seq 2 (uncommitted)

            reloaded = ExperimentLog(d)
            reloaded.reconcile(committed_events, committed_cmds)
            self.assertEqual(reloaded.event_seq, committed_events)
            self.assertEqual(reloaded.command_seq, committed_cmds)
            evs = read_lines(Path(d) / "events.jsonl")
            self.assertEqual([e["seq"] for e in evs], [1, 2])
            self.assertNotIn("c", [e["kind"] for e in evs])
            cmds = read_lines(Path(d) / "commands.jsonl")
            self.assertEqual([c["seq"] for c in cmds], [1])


class CrashResumeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Path(self.tmp.name)
        self.settings = load_settings()

    def tearDown(self):
        self.tmp.cleanup()

    def _inject_crash_tail(self, run_dir):
        """Append events/commands past last_committed_seq, as a crash would, then
        DON'T update state.json (mimicking death before _save)."""
        state = json.loads((run_dir / "state.json").read_text())
        ev_seq = state["last_committed_seq"]
        cmd_seq = state["checkpoint"]["safe_point"]["command_seq"]
        with open(run_dir / "events.jsonl", "a") as f:
            f.write(json.dumps({"seq": ev_seq + 1, "kind": "CRASH_TAIL_EVENT"}) + "\n")
            f.write(json.dumps({"seq": ev_seq + 2, "kind": "CRASH_TAIL_EVENT"}) + "\n")
        with open(run_dir / "commands.jsonl", "a") as f:
            f.write(json.dumps({"seq": cmd_seq + 1, "experiment_id": "GHOST", "tool": "t",
                                "version": "", "argv": [], "input_files": [], "env": {}, "cwd": ".",
                                "timeout": None, "nondeterministic": False, "dedup_key": "ghost",
                                "execution_status": "ok", "observation": "ghost"}) + "\n")

    def test_resume_has_no_duplicate_or_ghost_entries(self):
        sup = Supervisor("r", settings=self.settings, store_root=self.store).start([challenge()])
        sup.run(stop_after_steps=2)  # dispatch + first experiment, then checkpoint
        self._inject_crash_tail(sup.run_dir)
        del sup

        resumed = Supervisor.resume("r", settings=self.settings, store_root=self.store)
        self.assertEqual(resumed.run(), "completed")

        events = read_lines(resumed.run_dir / "events.jsonl")
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(seqs), len(set(seqs)), "duplicate event seqs after resume")
        self.assertNotIn("CRASH_TAIL_EVENT", [e["kind"] for e in events])

        commands = read_lines(resumed.run_dir / "commands.jsonl")
        self.assertNotIn("GHOST", [c.get("experiment_id") for c in commands])
        cmd_seqs = [c["seq"] for c in commands]
        self.assertEqual(len(cmd_seqs), len(set(cmd_seqs)), "duplicate command seqs after resume")

    def test_resume_matches_clean_run(self):
        sup = Supervisor("r", settings=self.settings, store_root=self.store).start([challenge()])
        sup.run(stop_after_steps=2)
        self._inject_crash_tail(sup.run_dir)
        del sup
        resumed = Supervisor.resume("r", settings=self.settings, store_root=self.store)
        resumed.run()
        clean = Supervisor("clean", settings=self.settings, store_root=self.store).start([challenge()])
        clean.run()
        self.assertEqual(
            (resumed.run_dir / "commands.jsonl").read_bytes(),
            (clean.run_dir / "commands.jsonl").read_bytes(),
        )
        rs = json.loads((resumed.run_dir / "state.json").read_text())
        cs = json.loads((clean.run_dir / "state.json").read_text())
        self.assertEqual(rs["results"], cs["results"])


if __name__ == "__main__":
    unittest.main()
