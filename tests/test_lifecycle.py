import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.classifier import classify  # noqa: E402
from orchestrator.router import route  # noqa: E402
from orchestrator.supervisor import Supervisor, load_settings  # noqa: E402


class ManualClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def crypto_challenge():
    return {
        "id": "chal-rsa",
        "name": "baby rsa",
        "description": "Small RSA modulus. Decrypt the ciphertext.",
        "files": ["output.txt", "params.sage"],
        "scenario": {
            "expected_flag": "hitcon{mock_flag}",
            "hypotheses": [
                {   # listed first but mid band -> must be tried second
                    "statement": "n has a factor findable by ECM",
                    "rationale": "n looks unbalanced",
                    "refutation_condition": "ECM B1=1e6 finds nothing",
                    "priority_band": "mid",
                    "flag": "hitcon{mock_flag}",
                    "experiments": [
                        {"tool": "factor", "version": "9.4", "argv": ["n.txt"],
                         "observation": "no small factor", "judgment": "inconclusive", "duration_s": 2},
                        {"tool": "ecm", "version": "7.0", "argv": ["-c", "100", "n.txt"],
                         "observation": "factor found", "judgment": "support", "duration_s": 3},
                    ],
                },
                {
                    "statement": "e=3 and m^3 < n (cube root)",
                    "rationale": "e is tiny",
                    "refutation_condition": "integer cube root of c is not exact",
                    "priority_band": "high",
                    "experiments": [
                        # tool crash: scenario says 'refute' but it must become inconclusive
                        {"tool": "python3", "version": "3.12", "argv": ["cube_root.py", "c.txt"],
                         "execution_status": "error", "observation": "Traceback", "judgment": "refute"},
                        {"tool": "python3", "version": "3.12", "argv": ["cube_root.py", "--fixed", "c.txt"],
                         "observation": "root not exact", "judgment": "refute"},
                    ],
                },
                {
                    "statement": "never reached",
                    "priority_band": "low",
                    "experiments": [{"tool": "noop", "argv": []}],
                },
            ],
        },
    }


def web_challenge():
    return {
        "id": "chal-web",
        "name": "login",
        "description": "Flask app with a session cookie.",
        "files": ["app/index.html"],
        "scenario": {
            "expected_flag": "hitcon{web}",
            "hypotheses": [{
                "statement": "weak flask secret",
                "priority_band": "high",
                "experiments": [
                    {"tool": "curl", "argv": ["-s", "http://target/"], "observation": "200", "judgment": "inconclusive"},
                    {"tool": "flask-unsign", "argv": ["--unsign"], "observation": "no hit", "judgment": "inconclusive"},
                ],
            }],
        },
    }


def challenges():
    return [crypto_challenge(), web_challenge()]


def read(path):
    return Path(path).read_bytes()


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = load_settings()

    def tearDown(self):
        self.tmp.cleanup()

    def new(self, store, run_id="run-001", clock=None):
        return Supervisor(run_id, settings=self.settings, store_root=store, clock=clock or ManualClock())

    def test_classify_and_route(self):
        self.assertEqual(classify(crypto_challenge()), "crypto")
        self.assertEqual(route("crypto"), "crypto_lane")
        self.assertEqual(classify(web_challenge()), "web")
        self.assertEqual(classify({"name": "x", "description": "", "files": []}), "misc")
        self.assertEqual(route("misc"), "generic_lane")

    def test_full_run(self):
        sup = self.new(self.root / "a").start(challenges())
        self.assertEqual(sup.run(), "completed")
        state = json.loads((sup.run_dir / "state.json").read_text())
        rsa = state["results"]["chal-rsa"]
        self.assertEqual(rsa["outcome"], "solved")
        self.assertEqual(rsa["lane"], "crypto_lane")
        hyps = {h["id"]: h for h in rsa["hypotheses"]}
        # high band hypothesis was tried first (H0) and refuted only by the clean run
        self.assertEqual(hyps["chal-rsa-H0"]["priority_band"], "high")
        self.assertEqual(hyps["chal-rsa-H0"]["status"], "refuted")
        self.assertEqual(hyps["chal-rsa-H1"]["status"], "supported")
        self.assertEqual(hyps["chal-rsa-H2"]["status"], "proposed")
        exps = {e["id"]: e for e in rsa["experiments"]}
        self.assertEqual(exps["chal-rsa-H0-E0"]["execution_status"], "error")
        self.assertEqual(exps["chal-rsa-H0-E0"]["hypothesis_judgment"], "inconclusive")
        self.assertEqual(exps["chal-rsa-H0-E1"]["hypothesis_judgment"], "refute")
        self.assertEqual(rsa["candidates"][0]["status"], "VERIFIED")
        web = state["results"]["chal-web"]
        self.assertEqual(web["outcome"], "unsolved")
        self.assertEqual(web["hypotheses"][0]["status"], "held")
        self.assertEqual(state["checkpoint"]["next_action"], {"kind": "done"})
        self.assertEqual(state["checkpoint"]["budget_spent"]["rounds"], 2)
        self.assertEqual(state["checkpoint"]["budget_spent"]["attempts"], 6)
        for name in ("state.json", "events.jsonl", "commands.jsonl"):
            self.assertTrue((sup.run_dir / name).exists(), name)

    def test_interrupt_and_resume_same_point(self):
        store = self.root / "b"
        sup = self.new(store).start(challenges())
        # steps: dispatch, H0-E0, H0-E1 -> interrupt
        self.assertEqual(sup.run(stop_after_steps=3), "interrupted")
        saved = json.loads((sup.run_dir / "state.json").read_text())
        cp = saved["checkpoint"]
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(cp["challenge_id"], "chal-rsa")
        self.assertEqual(cp["next_action"], {"kind": "experiment", "queue_index": 0, "hyp_index": 1, "exp_index": 0})
        self.assertEqual(cp["active_hypotheses"][0]["status"], "refuted")
        self.assertEqual(cp["safe_point"]["command_seq"], 2)
        commands_before = read(sup.run_dir / "commands.jsonl")
        del sup  # simulate process exit

        resumed = Supervisor.resume("run-001", settings=self.settings, store_root=store, clock=ManualClock())
        self.assertEqual(resumed.cp.next_action, cp["next_action"])
        self.assertEqual(resumed.cp.budget_spent, cp["budget_spent"])
        self.assertEqual(resumed.run(), "completed")
        # no experiment re-ran: commands.jsonl was only appended to
        commands_after = read(resumed.run_dir / "commands.jsonl")
        self.assertTrue(commands_after.startswith(commands_before))
        ids = [json.loads(l)["experiment_id"] for l in commands_after.splitlines()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[2], "chal-rsa-H1-E0")  # first work after resume = saved next_action

        # resumed result == uninterrupted result
        ref = self.new(self.root / "c").start(challenges())
        ref.run()
        s_resumed = json.loads((resumed.run_dir / "state.json").read_text())
        s_ref = json.loads((ref.run_dir / "state.json").read_text())
        self.assertEqual(s_resumed["results"], s_ref["results"])
        self.assertEqual(s_resumed["checkpoint"]["budget_spent"], s_ref["checkpoint"]["budget_spent"])
        self.assertEqual(commands_after, read(ref.run_dir / "commands.jsonl"))

    def test_deterministic_two_runs(self):
        dirs = []
        for name in ("d1", "d2"):
            sup = self.new(self.root / name).start(challenges())
            self.assertEqual(sup.run(), "completed")
            dirs.append(sup.run_dir)
        for f in ("state.json", "events.jsonl", "commands.jsonl"):
            self.assertEqual(read(dirs[0] / f), read(dirs[1] / f), f)

    def test_start_refuses_to_overwrite(self):
        store = self.root / "e"
        self.new(store).start(challenges())
        with self.assertRaises(FileExistsError):
            self.new(store).start(challenges())


if __name__ == "__main__":
    unittest.main()
