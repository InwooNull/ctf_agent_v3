"""Phase 50a: parallel runs must not collide on the docker container --name.

Two concurrent experiments that share an execution_id (two blind runs of the same
challenge both naming an experiment the same, e.g. "e01") previously reused the fixed
container name `ctfagent_<cid>-e01` and failed with "container name already in use",
wasting an experiment. run_tool now appends a fresh uuid to the name, so parallel runs
never collide. Offline / no live solver (a docker harness test; no Claude tokens).
"""
import sys
import tempfile
import threading
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
import json  # noqa: E402
from solver.misc_harness import MiscHarness  # noqa: E402
from tools import sandbox  # noqa: E402

_IMG = next((f"ctfagent-misc:{v}" for v in ("0.1", "0.2", "0.3", "0.4", "0.5")
             if sandbox.image_available(f"ctfagent-misc:{v}")), None)
_DOCKER = sandbox.docker_available() and _IMG is not None

CODE = 'print("CONTAINER_RUN_OK")'


def _chal(tmp):
    d = Path(tmp) / "mr_name"
    d.mkdir(parents=True)
    (d / "challenge.json").write_text(json.dumps(
        {"id": "mr_name", "category": "misc", "files": [], "description": "x", "flag_format": "flag{...}"}))
    return d


@unittest.skipUnless(_DOCKER, "no misc image built locally")
class TestNoContainerNameCollision(unittest.TestCase):
    def test_two_concurrent_same_exp_name_both_ok(self):
        with tempfile.TemporaryDirectory() as t:
            chal = _chal(t)
            results = {}

            def run(tag):
                # SAME challenge_id + SAME experiment name "e01" => identical execution_id
                # across the two runs: the exact pre-fix collision scenario.
                h = MiscHarness(tag, chal, store_root=Path(t) / tag, image=_IMG)
                o = h.run_experiment({"name": "e01", "code": CODE, "timeout": 60})
                results[tag] = (o.execution_status, o.stdout)

            a = threading.Thread(target=run, args=("runA",))
            b = threading.Thread(target=run, args=("runB",))
            a.start(); b.start(); a.join(); b.join()

            for tag in ("runA", "runB"):
                status, out = results[tag]
                self.assertEqual(status, "ok", f"{tag} failed: {out}")
                self.assertIn("CONTAINER_RUN_OK", out)
                self.assertNotIn("already in use", out)


if __name__ == "__main__":
    unittest.main()
