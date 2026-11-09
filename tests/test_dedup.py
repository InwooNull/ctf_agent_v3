import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.supervisor import Supervisor, load_settings  # noqa: E402
from solver.experiment_log import ExperimentLog, compute_dedup_key  # noqa: E402


class CountingExecutor:
    def __init__(self, status="ok"):
        self.calls = 0
        self.status = status

    def __call__(self, spec):
        self.calls += 1
        return self.status, f"out#{self.calls}"


def spec(**over):
    s = {"tool": "python3", "version": "3.12", "argv": ["solve.py", "-n", "3"], "env": {"PWNLIB_NOTERM": "1"},
         "cwd": "/work", "timeout": 30, "input_files": [], "nondeterministic": False}
    s.update(over)
    return s


class DedupKeyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def key(self, s):
        return compute_dedup_key(s["tool"], s["version"], s["argv"], s["input_files"], s["env"], s["timeout"], s["cwd"])

    def test_key_is_stable(self):
        self.assertEqual(self.key(spec()), self.key(spec()))
        self.assertEqual(self.key(spec(env={"A": "1", "B": "2"})), self.key(spec(env={"B": "2", "A": "1"})))

    def test_each_component_changes_key(self):
        base = self.key(spec())
        for over in ({"tool": "sage"}, {"version": "3.11"}, {"argv": ["solve.py", "-n", "4"]},
                     {"argv": ["-n", "3", "solve.py"]}, {"env": {"PWNLIB_NOTERM": "0"}},
                     {"timeout": 60}, {"cwd": "/other"}):
            self.assertNotEqual(self.key(spec(**over)), base, over)

    def test_input_file_content_changes_key(self):
        f = self.dir / "chall.bin"
        f.write_bytes(b"AAAA")
        k1 = self.key(spec(input_files=[str(f)]))
        f.write_bytes(b"BBBB")
        k2 = self.key(spec(input_files=[str(f)]))
        self.assertNotEqual(k1, k2)


class DedupCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.log = ExperimentLog(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_same_spec_served_from_cache(self):
        ex = CountingExecutor()
        r1 = self.log.run("E1", spec(), ex)
        r2 = self.log.run("E2", spec(), ex)
        self.assertEqual(ex.calls, 1)
        self.assertFalse(r1["cached"])
        self.assertTrue(r2["cached"])
        self.assertEqual(r1["observation"], r2["observation"])
        self.assertEqual(r1["observation_ref"], r2["observation_ref"])
        self.assertEqual(len((self.dir / "commands.jsonl").read_text().splitlines()), 1)

    def test_different_spec_reexecutes(self):
        ex = CountingExecutor()
        self.log.run("E1", spec(), ex)
        r = self.log.run("E2", spec(argv=["solve.py", "-n", "5"]), ex)
        self.assertEqual(ex.calls, 2)
        self.assertFalse(r["cached"])

    def test_nondeterministic_not_cached(self):
        ex = CountingExecutor()
        self.log.run("E1", spec(nondeterministic=True), ex)
        r = self.log.run("E2", spec(nondeterministic=True), ex)
        self.assertEqual(ex.calls, 2)
        self.assertFalse(r["cached"])
        # and a nondeterministic run does not poison the cache for the deterministic spec
        self.log.run("E3", spec(), ex)
        self.assertEqual(ex.calls, 3)

    def test_timeout_not_cached(self):
        ex = CountingExecutor(status="timeout")
        self.log.run("E1", spec(), ex)
        self.log.run("E2", spec(), ex)
        self.assertEqual(ex.calls, 2)

    def test_error_not_cached(self):
        # Phase 1: error is transient-ish and must be retried, never served from cache.
        ex = CountingExecutor(status="error")
        self.log.run("E1", spec(), ex)
        self.log.run("E2", spec(), ex)
        self.assertEqual(ex.calls, 2)
        # a later ok run of the same spec is cached normally
        ok = CountingExecutor(status="ok")
        r1 = self.log.run("E3", spec(), ok)
        r2 = self.log.run("E4", spec(), ok)
        self.assertFalse(r1["cached"])
        self.assertTrue(r2["cached"])

    def test_cache_survives_reload(self):
        ex = CountingExecutor()
        self.log.run("E1", spec(), ex)
        reloaded = ExperimentLog(self.dir)
        r = reloaded.run("E2", spec(), ex)
        self.assertTrue(r["cached"])
        self.assertEqual(ex.calls, 1)


class SupervisorDedupTest(unittest.TestCase):
    def test_duplicate_experiment_across_hypotheses(self):
        same = {"tool": "file", "version": "5.45", "argv": ["chall"], "observation": "ELF 64-bit", "judgment": "inconclusive"}
        challenge = {"id": "c1", "name": "dup", "description": "", "files": [], "scenario": {"hypotheses": [
            {"statement": "a", "priority_band": "high", "experiments": [dict(same)]},
            {"statement": "b", "priority_band": "mid", "experiments": [dict(same, judgment="refute")]},
        ]}}
        with tempfile.TemporaryDirectory() as tmp:
            sup = Supervisor("run-dedup", settings=load_settings(), store_root=tmp).start([challenge])
            self.assertEqual(sup.run(), "completed")
            self.assertEqual(sup.executions, 1)
            self.assertEqual(sup._solver.execution_count, 1)
            state = json.loads((sup.run_dir / "state.json").read_text())
            self.assertEqual(state["checkpoint"]["budget_spent"]["attempts"], 1)
            exps = state["results"]["c1"]["experiments"]
            self.assertEqual(exps[0]["dedup_key"], exps[1]["dedup_key"])
            # cached observation re-judged per hypothesis
            self.assertEqual([e["hypothesis_judgment"] for e in exps], ["inconclusive", "refute"])


if __name__ == "__main__":
    unittest.main()
