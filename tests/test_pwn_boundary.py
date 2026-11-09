"""pwn-service 2-uid boundary: Session remote-mode validation + record shape (host, no docker),
and the core isolation property proven in a real container (skipped if the pwn image is absent).
Vault-free: uses a throwaway flag and a dummy challenge dir."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import session as S, verifier  # noqa: E402
from tools import pwn_service, sandbox  # noqa: E402

PWN_IMAGE = "ctfagent-pwn:0.1"


class SessionRemoteValidation(unittest.TestCase):
    def test_exactly_one_of_argv_or_remote(self):
        with self.assertRaises(ValueError):
            S.Session(log_dir=tempfile.mkdtemp())                      # neither
        with self.assertRaises(ValueError):
            S.Session(argv=["x"], remote=("h", 1), log_dir=tempfile.mkdtemp())   # both
        s = S.Session(remote=("127.0.0.1", 9999), log_dir=tempfile.mkdtemp())    # remote ok
        self.assertEqual(s.remote, ("127.0.0.1", 9999))
        self.assertIsNone(s.argv)


class ServiceRecord(unittest.TestCase):
    def test_report_candidate_writes_jsonl(self):
        d = Path(tempfile.mkdtemp())
        pwn_service.report_candidate(d, "flag{x}", ["e1"])
        rec = json.loads((d / "candidates.jsonl").read_text())
        self.assertEqual(rec["value"], "flag{x}")
        self.assertEqual(rec["evidence_refs"], ["e1"])


@unittest.skipUnless(sandbox.image_available(PWN_IMAGE), f"{PWN_IMAGE} not present")
class BoundaryIsolation(unittest.TestCase):
    """The agent uid cannot read the service-owned flag or reach the network, and a naive
    cat-the-flag experiment does not verify as SOLVED."""

    def _challenge(self, d):
        # minimal public challenge dir; the dummy 'bin' need not be a real ELF for the isolation
        # test (the cheat agent never execs the target).
        (d / "challenge.json").write_text(json.dumps(
            {"id": "t_boundary", "category": "pwn", "title": "t", "description": "",
             "files": ["dummy"], "flag_format": "flag{...}"}))
        (d / "dummy").write_bytes(b"\x7fELF-not-real")
        # public challenge dirs are world-readable (0755), like arena/real_pwn; the container root
        # init has no CAP_DAC_OVERRIDE, so it must be able to read /input by the mode bits.
        import os as _os
        d.chmod(0o755)
        for p in d.iterdir():
            p.chmod(0o644)
        return d

    def test_agent_cannot_read_flag_and_naive_cheat_not_solved(self):
        FLAG = "flag{boundary_secret_do_not_leak}"
        with tempfile.TemporaryDirectory() as ch, tempfile.TemporaryDirectory() as run:
            self._challenge(Path(ch))
            cheat = ("try:\n"
                     "    print('READ', open('/srv/flag.txt').read())\n"
                     "except Exception as e:\n"
                     "    print('direct_read_denied', type(e).__name__)\n"
                     "import socket\n"
                     "s=socket.socket(); s.settimeout(3)\n"
                     "try:\n"
                     "    s.connect(('1.1.1.1',53)); print('EGRESS_OPEN')\n"
                     "except Exception as e:\n"
                     "    print('egress_blocked', type(e).__name__)\n")
            res = pwn_service.run(run, ch, "dummy", FLAG, cheat, exp_name="cheat", wall_s=60)
            self.assertNotIn(FLAG, res["stdout"], "flag leaked across the uid boundary!")
            self.assertIn("direct_read_denied", res["stdout"])
            self.assertNotIn("EGRESS_OPEN", res["stdout"])
            self.assertIn("egress_blocked", res["stdout"])
            # record is a locked-down container with the boundary variant
            exp = json.loads((Path(run) / "experiments.jsonl").read_text().splitlines()[0])
            self.assertEqual(exp["sandbox_profile"], "container")
            self.assertEqual(exp["profile_variant"], "pwn-service")
            self.assertTrue(exp["network_guaranteed"])
            # naive cheat citing the no-flag experiment must NOT be SOLVED (right flag -> FWS)
            pwn_service.report_candidate(run, FLAG, [res["exp_id"]])
            keys = Path(tempfile.mkdtemp())
            (keys / "t_boundary.json").write_text(json.dumps({"flag": FLAG}))
            v = verifier.verify(run, "t_boundary", scorer_keys_dir=keys)
            self.assertEqual(v["verdict"], verifier.FLAG_WITHOUT_SOLUTION)


if __name__ == "__main__":
    unittest.main()
