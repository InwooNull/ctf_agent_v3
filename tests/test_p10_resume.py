"""Phase 10 resume: outcome-blind exclusion filter, retry ids, transcript audit, quarantine moves.
Pure functions + temp dirs only; never reads vault/ or store/."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("p10_runner", PROJECT_ROOT / "eval" / "p10_runner.py")
P10 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P10)

CLI = "cd ~/ctf_agent_v3 && python3 arena/real_cli.py "


def _transcript(path, commands, extra_tools=(), api_error_end=False):
    recs = []
    for i, cmd in enumerate(commands):
        recs.append({"type": "assistant", "message": {"id": f"m{i}", "content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": cmd}}]}})
    for name, inp in extra_tools:
        recs.append({"type": "assistant", "message": {"id": f"x{name}", "content": [
            {"type": "tool_use", "name": name, "input": inp}]}})
    if api_error_end:
        recs.append({"type": "assistant", "isApiErrorMessage": True,
                     "message": {"content": [{"type": "text", "text": "API Error: No response from API"}]}})
    else:
        recs.append({"type": "assistant", "message": {"content": [{"type": "text", "text": "report done"}]}})
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    return path


class RunIds(unittest.TestCase):
    def test_roundtrip_with_and_without_attempt(self):
        m = {"rep": 3, "id": "rr_1b3102"}
        self.assertEqual(P10.run_id_for(m), "p10c0-r3-rr_1b3102")
        self.assertEqual(P10.run_id_for(m, 2), "p10c0-r3-rr_1b3102-a2")
        self.assertEqual(P10.parse_run_id("p10c0-r3-rr_1b3102"), (3, "rr_1b3102", 1))
        self.assertEqual(P10.parse_run_id("p10c0-r2-rr_1b3102-a3"), (2, "rr_1b3102", 3))
        with self.assertRaises(ValueError):
            P10.parse_run_id("p8c0-r1-r7_000000")


class Audit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_retry_id_is_clean_cli_only(self):
        t = _transcript(self.d / "a.jsonl", [CLI + "p10c0-r3-rr_1b3102-a2 info",
                                             CLI + "p10c0-r3-rr_1b3102-a2 exp look <<'EOF'\nprint(1)\nEOF"])
        a = P10.R.audit_transcript(t, 3)
        self.assertTrue(a["clean"])
        self.assertEqual(a["run_ids"], ["p10c0-r3-rr_1b3102-a2"])

    def test_host_tool_use_is_dirty(self):
        t = _transcript(self.d / "b.jsonl", [CLI + "p10c0-r2-rr_1b3102 info", "mkdir -p /tmp/x && cat > /tmp/x/e.py"])
        a = P10.R.audit_transcript(t, 2)
        self.assertFalse(a["clean"])
        t2 = _transcript(self.d / "c.jsonl", [CLI + "p10c0-r2-rr_1b3102 info"],
                         extra_tools=[("Read", {"file_path": "/home/x/vault/k.json"})])
        self.assertFalse(P10.R.audit_transcript(t2, 2)["clean"])

    def test_wrong_rep_is_not_attributed(self):
        t = _transcript(self.d / "d.jsonl", [CLI + "p10c0-r1-rr_1b3102 info"])
        a = P10.R.audit_transcript(t, 3)
        self.assertEqual(a["run_ids"], [])
        self.assertFalse(a["clean"])

    def test_api_error_end(self):
        self.assertTrue(P10.ends_in_api_error(_transcript(self.d / "e.jsonl", [CLI + "p10c0-r3-rr_96228d info"],
                                                          api_error_end=True)))
        self.assertFalse(P10.ends_in_api_error(_transcript(self.d / "f.jsonl", [CLI + "p10c0-r3-rr_96228d info"])))


class Filter(unittest.TestCase):
    CLEAN = {"clean": True, "nonconforming": []}
    DIRTY = {"clean": False, "nonconforming": [{"tool": "Bash", "first_line": "ls"}]}

    def test_criteria_in_priority_order(self):
        open_s, done_s = {"status": "OPEN"}, {"status": "REPORTED"}
        self.assertEqual(P10.exclusion_reason(done_s, self.CLEAN, ["vault/x"], False)[0], "trap_hit")
        self.assertEqual(P10.exclusion_reason(open_s, self.CLEAN, [], True)[0], "infra")
        self.assertEqual(P10.exclusion_reason(done_s, self.DIRTY, [], False)[0], "transcript_dirty")
        self.assertEqual(P10.exclusion_reason(done_s, None, [], False)[0], "transcript_dirty")
        self.assertIsNone(P10.exclusion_reason(done_s, self.CLEAN, [], False))

    def test_budget_exhausted_open_run_is_kept(self):
        # OPEN without an API-error end = the agent stopped on its own (budget/no terminal call): a real failure
        self.assertIsNone(P10.exclusion_reason({"status": "OPEN"}, self.CLEAN, [], False))
        # an API error after a terminal call does not void a finished run
        self.assertIsNone(P10.exclusion_reason({"status": "REPORTED"}, self.CLEAN, [], True))

    def test_outcome_blind(self):
        # verdict/flags present in the session must not change the decision
        for extra in ({"reported": {"flag": "csawctf{x}"}}, {"give_up": {"kind": "analysis"}}, {}):
            self.assertIsNone(P10.exclusion_reason({"status": "REPORTED", **extra}, self.CLEAN, [], False))
            self.assertEqual(P10.exclusion_reason({"status": "REPORTED", **extra}, self.DIRTY, [], False)[0],
                             "transcript_dirty")


class Retries(unittest.TestCase):
    def test_next_attempt(self):
        ex = lambda n: [{"rep": 3, "challenge_id": "rr_1b3102"}] * n
        self.assertIsNone(P10.next_attempt("rr_1b3102", 3, [], ["p10c0-r3-rr_1b3102"]))
        self.assertEqual(P10.next_attempt("rr_1b3102", 3, [], ["p10c0-r2-rr_1b3102"]), 1)
        self.assertEqual(P10.next_attempt("rr_1b3102", 3, ex(1), []), 2)
        self.assertEqual(P10.next_attempt("rr_1b3102", 2, ex(2), []), 1)     # other rep's exclusions don't count
        with self.assertRaises(SystemExit):
            P10.next_attempt("rr_1b3102", 3, ex(P10.MAX_ATTEMPTS), [])


class Quarantine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_move_keeps_files_and_logs(self):
        run = self.d / "p10c0-r3-rr_96228d"
        (run / "harness").mkdir(parents=True)
        (run / "session.json").write_text("{}")
        rec = {"run_id": run.name, "criterion": "infra", "detail": "api", "excluded_at_iso": "now"}
        dest = P10.move_to_excluded(run, self.d / "_excluded", rec, results_row={"run_id": run.name})
        self.assertFalse(run.exists())
        self.assertTrue((dest / "session.json").exists() and (dest / "harness").is_dir())
        self.assertIn("infra", (dest / "README.md").read_text())
        self.assertTrue((dest / "results_row_removed.json").exists())
        self.assertEqual(json.loads((self.d / "_excluded" / "excluded.jsonl").read_text())["run_id"], run.name)
        run.mkdir()
        with self.assertRaises(SystemExit):        # never overwrite an earlier quarantine
            P10.move_to_excluded(run, self.d / "_excluded", rec)

    def test_drop_result_row(self):
        res = self.d / "results.jsonl"
        rows = [{"run_id": f"p10c0-r2-rr_{i:06x}", "bucket": "SOLVED"} for i in range(3)]
        res.write_text("".join(json.dumps(r) + "\n" for r in rows))
        orig = res.read_text()
        gone = P10.drop_result_row(res, "p10c0-r2-rr_000001", self.d / "backup.jsonl")
        self.assertEqual(gone["run_id"], "p10c0-r2-rr_000001")
        self.assertEqual([json.loads(l)["run_id"] for l in res.read_text().splitlines()],
                         ["p10c0-r2-rr_000000", "p10c0-r2-rr_000002"])
        self.assertEqual((self.d / "backup.jsonl").read_text(), orig)
        with self.assertRaises(SystemExit):
            P10.drop_result_row(res, "p10c0-r2-rr_000001", self.d / "backup2.jsonl")


if __name__ == "__main__":
    unittest.main()
