"""Phase CM7: route file analysis to tool-equipped images.

Proof that a pcap is solved by the REAL tool (tshark) in the tool image, not the
strings fallback: the flag is gzip-compressed inside the UDP payload, so the CM6 default
byte scanner finds NOTHING, while the CM7 tshark route extracts + decompresses it. A
family whose tool image is absent falls back to the scanner AND logs a need.
"""
import gzip
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import contest_run as crun             # noqa: E402
from orchestrator import contest_files as cf             # noqa: E402
from tools import sandbox                                 # noqa: E402

_MISC_READY = sandbox.container_backend_ready(cf.MISC_IMAGE)
PCAP_FLAG = "flag{tshark_gzip_pcap}"


def _make_gzip_pcap(path):
    payload = gzip.compress(PCAP_FLAG.encode())
    udp = struct.pack("!HHHH", 4444, 9999, 8 + len(payload), 0) + payload
    ip = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0)
          + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]))
    eth = b"\x11\x22\x33\x44\x55\x66" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x00"
    frame = eth + ip + udp
    gh = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 0, 0, len(frame), len(frame))
    Path(path).write_bytes(gh + rec + frame)


CAPS = {"experiments": 4, "wall_s": 1200.0, "tokens": 0}
GLOBAL = {"experiments": 100, "time_s": 1e9}


class TestAnalyzerRouting(unittest.TestCase):
    def test_family_to_image_mapping(self):
        img, key, _, fb, _ = cf.resolve_analyzer("pcap", available=lambda i: True)
        self.assertEqual((img, key, fb), (cf.MISC_IMAGE, "tshark", False))
        img, key, _, fb, _ = cf.resolve_analyzer("binary", available=lambda i: True)
        self.assertEqual((img, key, fb), (cf.REV_IMAGE, "rev", False))

    def test_text_uses_default_scanner(self):
        img, key, _, fb, _ = cf.resolve_analyzer("text", available=lambda i: True)
        self.assertEqual(key, "scan")
        self.assertFalse(fb)

    def test_absent_tool_image_falls_back_with_reason(self):
        img, key, _, fb, reason = cf.resolve_analyzer("pcap", available=lambda i: False)
        self.assertTrue(fb)
        self.assertEqual(key, "scan")
        self.assertIn("tool_image_unavailable", reason)


@unittest.skipUnless(_MISC_READY, "ctfagent-misc image not available")
class TestPcapViaTsharkE2E(unittest.TestCase):
    def test_gzip_flag_solved_by_tshark_not_strings(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as store:
            root = Path(d)
            (root / "c_pcap").mkdir()
            _make_gzip_pcap(root / "c_pcap" / "t.pcap")

            # strings fallback (CM6 default scanner) must find NOTHING (flag is gzip'd)
            scan_out, st = cf.sandbox_scan(root / "c_pcap", ["t.pcap"],
                                           Path(store) / "scanjail", "cm7scan")
            self.assertEqual(st, "ok")
            self.assertNotIn("flag{", scan_out)

            # the tool route (tshark in misc image) extracts + decompresses the flag
            items = cf.file_items_from_input(str(root))
            self.assertEqual(items[0]["family"], "pcap")
            pipe = crun.ContestPipeline(items, store, "cm7e2e", model="claude-opus-4-8",
                                        global_caps=GLOBAL, challenge_caps=CAPS,
                                        slice_rounds=2, no_progress_k=2)
            summ = pipe.run()
            run_dir = Path(summ["run_dir"])

            self.assertEqual(summ["status"]["c_pcap"], "solved")
            ver = summ["verified_candidates"][0]
            self.assertEqual(ver["flag"], PCAP_FLAG)

            # evidence came from the tshark analyzer in the misc image (not fallback)
            ev_ref = ver["evidence_refs"][0]
            idx = {json.loads(l)["id"]: json.loads(l) for l in
                   (run_dir / "c_pcap" / "evidence" / "evidence.jsonl").read_text().splitlines()}
            self.assertTrue(idx[ev_ref]["label"].startswith("tshark@ctfagent-misc"))
            self.assertNotIn("fallback", idx[ev_ref]["label"])


@unittest.skipUnless(_MISC_READY, "container backend not available")
class TestFallbackLogsNeed(unittest.TestCase):
    def test_tool_missing_falls_back_and_logs_need(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as store:
            root = Path(d)
            (root / "c_pcap").mkdir()
            _make_gzip_pcap(root / "c_pcap" / "t.pcap")
            run_dir = Path(store) / "contest" / "fb"
            from solver import contest_evidence as ce
            ctx = cf.FileChallengeCtx("c_pcap", "forensics",
                                      ce.ContestVerifier(run_dir / "c_pcap", "flag{...}"),
                                      "flag{...}", root / "c_pcap", ["t.pcap"],
                                      "p", run_dir / "c_pcap" / "work", "pcap", "tshark",
                                      run_dir=run_dir)
            # force every tool image "absent" -> fallback to the default scanner
            r = cf.file_solver(ctx, 0, {}, available=lambda img: False)
            # gzip'd flag is invisible to the scanner, so no solve, and a need is logged
            self.assertIsNone(r.get("candidate"))
            self.assertIn("FALLBACK", r["log"])
            needs = [json.loads(l) for l in (run_dir / "needs.jsonl").read_text().splitlines()]
            self.assertEqual(needs[0]["type"], "tool_gap")
            self.assertEqual(needs[0]["cid"], "c_pcap")


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
