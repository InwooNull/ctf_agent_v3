"""Phase CM6: file/folder contest input (download-artifact / WHITEHAT-shaped).

A local dummy fileset (text + pcap with a cleartext flag = solvable; a stego-ish PNG
with no cleartext flag = unsolvable). `solve ./dir --run` triages by magic byte, solves
each in the governance container sandbox, grounds the flag in the real execution output,
checkpoints, writes the writeup, and surfaces candidates for MANUAL submit. Interrupt ->
resume preserves all. Bench + governance untouched.
"""
import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import solve                                              # noqa: E402
from orchestrator import contest_run as crun             # noqa: E402
from orchestrator import contest_files as cf             # noqa: E402
from orchestrator import mode as mode_mod                 # noqa: E402
from solver import contest_evidence as ce                 # noqa: E402
from tools import sandbox                                  # noqa: E402

_CONTAINER = sandbox.container_backend_ready(
    sandbox.load_sandbox_config()["container"].get("image"))

TEXT_FLAG = "flag{file_text_solve}"
PCAP_FLAG = "flag{pcap_solve}"


def _real_pcap(payload):
    """A minimal but genuinely parseable Ethernet/IPv4/UDP pcap carrying `payload`
    (CM7 routes pcap -> tshark, which needs a real frame, not raw magic+bytes)."""
    udp = struct.pack("!HHHH", 4444, 9999, 8 + len(payload), 0) + payload
    ip = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0)
          + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]))
    eth = b"\x11\x22\x33\x44\x55\x66" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x00"
    frame = eth + ip + udp
    gh = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 0, 0, len(frame), len(frame))
    return gh + rec + frame


def _make_fileset(root):
    (root / "c_text").mkdir()
    (root / "c_text" / "notes.txt").write_text(f"intro\nthe secret is {TEXT_FLAG}\nbye\n")
    (root / "c_pcap").mkdir()
    (root / "c_pcap" / "cap.pcap").write_bytes(_real_pcap(PCAP_FLAG.encode()))
    (root / "c_stego").mkdir()
    (root / "c_stego" / "img.png").write_bytes(
        b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 2)      # no cleartext flag


CAPS = {"experiments": 4, "wall_s": 1200.0, "tokens": 0}
GLOBAL = {"experiments": 100, "time_s": 1e9}


class TestSniff(unittest.TestCase):
    def test_magic_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_fileset(root)
            self.assertEqual(cf.sniff(root / "c_text" / "notes.txt")[0], "text")
            self.assertEqual(cf.sniff(root / "c_pcap" / "cap.pcap")[0], "pcap")
            self.assertEqual(cf.sniff(root / "c_stego" / "img.png")[0], "image")

    def test_items_from_dir_are_per_subdir(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_fileset(root)
            items = cf.file_items_from_input(str(root))
        ids = sorted(i["id"] for i in items)
        self.assertEqual(ids, ["c_pcap", "c_stego", "c_text"])
        self.assertTrue(all(i["solve_kind"] == "file" for i in items))


@unittest.skipUnless(_CONTAINER, "container backend not ready")
class TestFilePracticeE2E(unittest.TestCase):
    def _run(self, root, store):
        items = cf.file_items_from_input(str(root))
        pipe = crun.ContestPipeline(items, store, "cm6e2e", model="claude-opus-4-8",
                                    global_caps=GLOBAL, challenge_caps=CAPS,
                                    slice_rounds=2, no_progress_k=2, record_experience=True)
        return pipe.run()

    def test_full_file_loop(self):
        import connector.ctfd_client as cc
        calls = []
        orig = cc.CTFdClient.submit_flag
        cc.CTFdClient.submit_flag = lambda self, *a, **k: calls.append(a) or ("correct", "")
        try:
            with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as store:
                root = Path(d)
                _make_fileset(root)
                summ = self._run(root, store)
                run_dir = Path(summ["run_dir"])

                self.assertEqual(summ["status"]["c_text"], "solved")
                self.assertEqual(summ["status"]["c_pcap"], "solved")
                self.assertEqual(summ["status"]["c_stego"], "stopped")

                ver = {c["cid"]: c for c in summ["verified_candidates"]}
                self.assertEqual(ver["c_text"]["flag"], TEXT_FLAG)
                self.assertEqual(ver["c_pcap"]["flag"], PCAP_FLAG)

                # evidence came from the sandbox EXECUTION OUTPUT (SRC_EXEC), on disk
                ev_ref = ver["c_text"]["evidence_refs"][0]
                ev = (run_dir / "c_text" / "evidence" / f"{ev_ref}.txt").read_text()
                self.assertIn(TEXT_FLAG, ev)
                idx = [json.loads(l) for l in
                       (run_dir / "c_text" / "evidence" / "evidence.jsonl").read_text().splitlines()]
                self.assertEqual(idx[0]["source"], ce.SRC_EXEC)

                # writeup + manual-only candidates + zero auto-submit
                self.assertTrue((run_dir / "writeup_log.jsonl").read_text().strip())
                self.assertTrue(all(c["submitted"] is False for c in summ["candidates"]))
        finally:
            cc.CTFdClient.submit_flag = orig
        self.assertEqual(calls, [])

    def test_solve_dir_run_cli(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as store:
            root = Path(d)
            _make_fileset(root)
            plan = solve.build_plan(str(root))
            self.assertEqual(plan["kind"], "dir")
            self.assertEqual(plan["mode"], mode_mod.CONTEST)
            rc = crun.run_plan(plan, store_root=store, run_id="cm6cli")
        self.assertEqual(rc, 0)

    def test_interrupt_resume(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as store:
            root = Path(d)
            _make_fileset(root)
            items = cf.file_items_from_input(str(root))
            p1 = crun.ContestPipeline(items, store, "cm6rz", global_caps=GLOBAL,
                                      challenge_caps=CAPS, slice_rounds=1, no_progress_k=2)
            s1 = p1.run(max_slices=1)
            state1 = json.loads((Path(s1["run_dir"]) / "state.json").read_text())["challenges"]
            p2 = crun.ContestPipeline(items, store, "cm6rz", global_caps=GLOBAL,
                                      challenge_caps=CAPS, slice_rounds=1, no_progress_k=2)
            s2 = p2.run()
        # solvable artifacts end solved; terminal-in-run1 stays terminal (no churn)
        self.assertEqual(set(s2["solved"]), {"c_text", "c_pcap"})
        for c, st in state1.items():
            if st["status"] in ("solved", "stopped"):
                self.assertIn(s2["status"][c], ("solved", "stopped"))


class TestGovernanceUntouched(unittest.TestCase):
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
