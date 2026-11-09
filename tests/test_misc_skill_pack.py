"""Phase 42 structure tests: the misc/forensics C1 knowledge pack exists, routes
signals to the right technique families + tools, and plugs into the existing
skill_pack injection mechanism unchanged; PLUS the Phase-42 FWS-guard unification
(the injected C1 prompt now carries the same no-guess / run-to-win rule as C0) and a
verifier check that an unverified candidate is NOT accepted as SOLVED.

Offline/fast (no container, no vault). The real in-container tool smokes + the
signal->tool routing TRACE live in eval/p42_misc_trace.py (image-gated), reported
separately — this test only locks structure + the anti-cheat/FWS invariants so they
can't silently rot.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack  # noqa: E402
from solver import verifier  # noqa: E402

DETAILS = ["archive.md", "crack.md", "disk.md", "encoding.md", "jail.md",
           "memory.md", "pcap.md", "qr_barcode.md", "stego.md"]


class TestMiscPack(unittest.TestCase):
    def test_pack_present(self):
        self.assertTrue(skill_pack.has_pack("misc"))
        self.assertEqual([p.name for p in skill_pack.detail_files("misc")], DETAILS)

    def test_router_routes_signals_to_tools(self):
        r = skill_pack.router_text("misc").lower()
        # named specialist tools the 0.3 image provides
        for tool in ("volatility3", "sleuthkit", "john", "zbar", "tshark",
                     "steghide", "zsteg", "binwalk", "foremost", "7z"):
            self.assertIn(tool, r)
        # hashcat present BUT flagged conditional (no-GPU / CPU-slow caveat)
        self.assertIn("hashcat", r)
        self.assertTrue("gpu" in r and ("cpu" in r or "slow" in r))
        # vol3 symbols flagged bundled/offline
        self.assertTrue("bundled" in r or "baked" in r)
        self.assertin_any(r, ("--network none", "offline"))
        # representative signal->family routes
        for sig in ("memory dump", "disk", "hash", "qr", "pcap", "stego",
                    "archive", "jail", "encoding"):
            self.assertIn(sig, r)

    def assertin_any(self, hay, needles):
        self.assertTrue(any(n in hay for n in needles),
                        f"none of {needles} in text")

    def test_detail_files_cover_conditions_and_tools(self):
        d = {p.name: p.read_text(encoding="utf-8").lower()
             for p in skill_pack.detail_files("misc")}
        self.assertIn("vol", d["memory.md"])
        self.assertTrue("windows" in d["memory.md"] and "offline" in d["memory.md"])
        self.assertTrue("fls" in d["disk.md"] and "icat" in d["disk.md"])
        self.assertTrue("john" in d["crack.md"] and "2john" in d["crack.md"])
        self.assertTrue("zbarimg" in d["qr_barcode.md"] or "pyzbar" in d["qr_barcode.md"])
        self.assertIn("tshark", d["pcap.md"])
        self.assertTrue("zsteg" in d["stego.md"] and "lsb" in d["stego.md"])
        self.assertTrue("binwalk" in d["archive.md"] and "foremost" in d["archive.md"])
        self.assertTrue("python" in d["jail.md"] and "__class__" in d["jail.md"])
        self.assertTrue("base64" in d["encoding.md"] and "brainfuck" in d["encoding.md"])
        # every detail file keeps a "verify before report" line (anti-FWS discipline)
        for name, txt in d.items():
            self.assertIn("verify", txt, f"{name} missing a verify step")

    def test_inject_appends_pack_to_c0_prompt(self):
        base = "BASE_C0_PROMPT"
        c1 = skill_pack.inject(base, "misc", full=True)
        self.assertTrue(c1.startswith(base))
        self.assertIn("skills/misc/SKILL.md", c1)
        for name in DETAILS:
            self.assertIn(f"skills/misc/{name}", c1)
        self.assertLess(len(skill_pack.load_pack("misc", full=False)),
                        len(skill_pack.load_pack("misc", full=True)))


class TestFwsGuardUnification(unittest.TestCase):
    """Phase 42 sec.0 (all-domain): the C1 (pack-injected) prompt must carry the same
    no-guess / run-to-win guard as the C0 base prompt, for EVERY category with a pack.
    Phase 41 regression: a C1 agent guessed a wrong flag after the pack text softened
    into "background" and dropped the guard."""

    GUARD_MARKERS = ("never report a guessed", "run-to-win", "not submittable")

    def test_inject_header_carries_fws_guard_all_categories(self):
        base = "BASE_C0_PROMPT"  # deliberately WITHOUT the guard
        for cat in ("misc", "crypto", "pwn", "reverse"):
            if not skill_pack.has_pack(cat):
                continue
            c1 = skill_pack.inject(base, cat, full=False).lower()
            for marker in self.GUARD_MARKERS:
                self.assertIn(marker, c1,
                              f"{cat} C1 prompt missing FWS-guard marker {marker!r}")

    def test_guard_is_in_the_injected_header_not_the_base(self):
        # the guard comes from inject(), so even a guard-less base becomes guarded
        base = "no guard here"
        c1 = skill_pack.inject(base, "misc", full=False).lower()
        self.assertNotIn("run-to-win", base.lower())
        self.assertIn("run-to-win", c1)


class TestUnverifiedCandidateBlocked(unittest.TestCase):
    """The structural anti-FWS backstop: even if an agent reports a candidate equal to
    the real flag, the verifier refuses SOLVED without a container evidence chain. A
    guessed/unverified flag can never pass."""

    def _run_dir(self, tmp, candidate_value, evidence_refs, experiments):
        run = Path(tmp)
        (run / "artifacts").mkdir(parents=True, exist_ok=True)
        with (run / "candidates.jsonl").open("w") as f:
            f.write(json.dumps({"value": candidate_value,
                                "evidence_refs": evidence_refs,
                                "status": "UNVERIFIED"}) + "\n")
        with (run / "experiments.jsonl").open("w") as f:
            for e in experiments:
                f.write(json.dumps(e) + "\n")
        return run

    def _keys_dir(self, tmp, cid, flag):
        kd = Path(tmp) / "keys"
        kd.mkdir(parents=True, exist_ok=True)
        (kd / f"{cid}.json").write_text(json.dumps({"flag": flag}))
        return kd

    def test_guessed_flag_without_evidence_is_flag_without_solution(self):
        cid, flag = "misc_dummy", "flag{correct_but_guessed}"
        with tempfile.TemporaryDirectory() as tmp:
            kd = self._keys_dir(tmp, cid, flag)
            # candidate equals the real flag, but NO experiment produced it
            run = self._run_dir(tmp, flag, evidence_refs=[], experiments=[])
            v = verifier.verify(run, cid, scorer_keys_dir=kd)
            self.assertEqual(v["verdict"], verifier.FLAG_WITHOUT_SOLUTION)
            self.assertFalse(v["solved"])

    def test_flag_backed_by_container_run_is_solved(self):
        cid, flag = "misc_dummy", "flag{produced_in_container}"
        with tempfile.TemporaryDirectory() as tmp:
            kd = self._keys_dir(tmp, cid, flag)
            run = Path(tmp)
            (run / "artifacts").mkdir(parents=True, exist_ok=True)
            (run / "artifacts" / "e1.out").write_text("... the tool printed " + flag + " ...")
            exp = {"exp_id": "e1", "sandbox_profile": "container",
                   "execution_status": "ok", "stdout_ref": "e1.out"}
            run = self._run_dir(tmp, flag, evidence_refs=["e1"], experiments=[exp])
            v = verifier.verify(run, cid, scorer_keys_dir=kd)
            self.assertEqual(v["verdict"], verifier.SOLVED)
            self.assertTrue(v["solved"])


if __name__ == "__main__":
    unittest.main()
