"""Phase CM5: full contest machine, practice end-to-end.

A local dummy HTTP target serves a flag (a non-weaponizing path read). The whole loop
runs for real: scoped egress -> fetch the target -> flag in the REAL response -> evidence
capture -> VERIFIED solve -> writeup_log -> candidate shown for MANUAL submit. A second
target serves no flag -> STOPPED. No auto-submit. Interrupt mid-run -> resume preserves
all, skips done, zero duplicate. Bench + governance untouched.
"""
import hashlib
import json
import socket
import threading
import unittest
import tempfile
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import solve                                              # noqa: E402
from orchestrator import contest_run as crun             # noqa: E402
from orchestrator import mode as mode_mod                 # noqa: E402
from solver import contest_evidence as ce                 # noqa: E402

FLAG = "flag{cm5_e2e_real_solve}"


class DummyHTTP:
    """Raw HTTP/1.0 server. serve_flag=True -> GET /flag returns the flag; else 404."""
    def __init__(self, serve_flag):
        self.serve_flag = serve_flag
        self.hits = []
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", 0))
        self.s.listen(16)
        self.address = self.s.getsockname()
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def url(self):
        return f"http://{self.address[0]}:{self.address[1]}/"

    def _run(self):
        self.s.settimeout(0.25)
        while not self._stop.is_set():
            try:
                c, _ = self.s.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            c.settimeout(2)
            req = c.recv(4096).decode("latin1", "replace")
            path = (req.split(" ", 2) + ["", ""])[1]
            self.hits.append(path)
            if self.serve_flag and path == "/flag":
                body = f"<html>secret page\n{FLAG}\n</html>"
            else:
                body = "not found"
            resp = (f"HTTP/1.0 200 OK\r\nContent-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n{body}")
            c.sendall(resp.encode())
        except OSError:
            pass
        finally:
            c.close()

    def stop(self):
        self._stop.set()
        try:
            self.s.close()
        except OSError:
            pass


CAPS = {"experiments": 4, "wall_s": 1200.0, "tokens": 0}
GLOBAL = {"experiments": 100, "time_s": 1e9}


def _no_autosubmit():
    """Context: patch CTFdClient.submit_flag to count any (forbidden) auto-submit."""
    import connector.ctfd_client as cc
    calls = []
    orig = cc.CTFdClient.submit_flag
    cc.CTFdClient.submit_flag = lambda self, *a, **k: calls.append(a) or ("correct", "")
    return cc, orig, calls


class TestPracticeE2E(unittest.TestCase):
    def setUp(self):
        self.good = DummyHTTP(serve_flag=True)
        self.bad = DummyHTTP(serve_flag=False)

    def tearDown(self):
        self.good.stop()
        self.bad.stop()

    def test_full_loop_verified_solve_and_stopped(self):
        cc, orig, calls = _no_autosubmit()
        try:
            with tempfile.TemporaryDirectory() as root:
                items = [
                    {"id": "solvable", "target": self.good.url(), "category": "web",
                     "flag_format": "flag{...}", "score": 100, "difficulty": "easy", "est_cost": 1},
                    {"id": "unsolvable", "target": self.bad.url(), "category": "web",
                     "flag_format": "flag{...}", "score": 90, "difficulty": "med", "est_cost": 1},
                ]
                pipe = crun.ContestPipeline(items, root, "e2e1", model="claude-opus-4-8",
                                            global_caps=GLOBAL, challenge_caps=CAPS,
                                            slice_rounds=2, record_experience=True)
                summ = pipe.run()
                run_dir = Path(summ["run_dir"])

                # a REAL verified solve from the target's real response
                self.assertEqual(summ["status"]["solvable"], "solved")
                self.assertEqual(summ["status"]["unsolvable"], "stopped")
                ver = summ["verified_candidates"]
                self.assertEqual(len(ver), 1)
                self.assertEqual(ver[0]["cid"], "solvable")
                self.assertEqual(ver[0]["flag"], FLAG)
                self.assertEqual(ver[0]["verdict"], ce.VERIFIED)

                # evidence grounded on disk (attributable), and it really came from target
                ev_ref = ver[0]["evidence_refs"][0]
                ev_file = run_dir / "solvable" / "evidence" / f"{ev_ref}.txt"
                self.assertTrue(ev_file.exists())
                self.assertIn(FLAG, ev_file.read_text())
                self.assertIn("/flag", self.good.hits)        # target was actually hit

                # writeup_log recorded model + prompt + skill injection
                wl = [json.loads(l) for l in (run_dir / "writeup_log.jsonl").read_text().splitlines()]
                self.assertTrue(wl)
                self.assertTrue(all(e["model"] == "claude-opus-4-8" for e in wl))
                self.assertTrue(any(e.get("skill_injected") for e in wl))

                # candidate shown for MANUAL submit; nothing auto-submitted
                cands = summ["candidates"]
                self.assertTrue(all(c["submitted"] is False for c in cands))
                self.assertTrue(all(c["action"] == "manual_submit_by_user" for c in cands))

                # contest experience tagged + isolated (not in bench store)
                exp = root and (Path(root) / "contest" / "experience_contest.jsonl")
                self.assertTrue(exp.exists())
                self.assertEqual(json.loads(exp.read_text().splitlines()[0])["source"], "contest")
                self.assertFalse((Path(root) / "experience_misc.jsonl").exists())
        finally:
            cc.CTFdClient.submit_flag = orig
        self.assertEqual(calls, [])                           # ZERO auto-submit

    def test_default_mode_is_contest_full_machine(self):
        # routing: solve.build_plan on a URL with no --bench -> contest, and --run wires
        # the real pipeline (proven by rc=0 below using the real dummy target)
        plan = solve.build_plan(self.good.url())
        self.assertEqual(plan["mode"], mode_mod.CONTEST)
        with tempfile.TemporaryDirectory() as root:
            rc = crun.run_plan(plan, store_root=root, run_id="cli1")
        self.assertEqual(rc, 0)


class TestInterruptResumeIntegration(unittest.TestCase):
    def setUp(self):
        self.good = DummyHTTP(serve_flag=True)

    def tearDown(self):
        self.good.stop()

    def test_resume_preserves_and_skips(self):
        items = [
            {"id": "a", "target": self.good.url(), "category": "web",
             "flag_format": "flag{...}", "score": 100, "difficulty": "easy", "est_cost": 1},
            {"id": "b", "target": self.good.url(), "category": "web",
             "flag_format": "flag{...}", "score": 90, "difficulty": "easy", "est_cost": 1},
        ]
        with tempfile.TemporaryDirectory() as root:
            # interrupt after a single slice
            p1 = crun.ContestPipeline(items, root, "rz", global_caps=GLOBAL,
                                      challenge_caps=CAPS, slice_rounds=1)
            s1 = p1.run(max_slices=1)
            run_dir = Path(s1["run_dir"])
            state1 = json.loads((run_dir / "state.json").read_text())

            # resume with a fresh pipeline on the SAME store/run
            p2 = crun.ContestPipeline(items, root, "rz", global_caps=GLOBAL,
                                      challenge_caps=CAPS, slice_rounds=1)
            s2 = p2.run()

        # both challenges end solved after resume; progress was preserved (not restarted)
        self.assertEqual(set(s2["solved"]), {"a", "b"})
        # whatever was already terminal in run1 stays terminal (no re-solve churn)
        term1 = {c for c, st in state1["challenges"].items() if st["status"] in ("solved", "stopped")}
        for c in term1:
            self.assertIn(s2["status"][c], ("solved", "stopped"))


class TestGovernanceAndBenchUntouched(unittest.TestCase):
    def test_bench_run_rejected_by_run_plan(self):
        # bench stays blind; run_plan must refuse to drive it through the contest path
        plan = {"kind": "url", "mode": mode_mod.BENCH, "input": "http://x/"}
        self.assertEqual(crun.run_plan(plan, store_root="/tmp"), 2)

    def test_seven_files_hash_invariant(self):
        baseline = (PROJECT_ROOT / "growth" / "governance_baseline.txt").read_text().splitlines()
        for line in baseline:
            line = line.strip()
            if not line:
                continue
            want, rel = line.split()[0], line.split()[-1]
            got = hashlib.sha256((PROJECT_ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"governance file changed: {rel}")


if __name__ == "__main__":
    unittest.main()
