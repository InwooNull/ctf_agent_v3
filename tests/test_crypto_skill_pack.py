"""Phase 37 structure tests: the crypto C1 knowledge pack exists, routes signals to
techniques/tools, and plugs into the existing skill_pack injection mechanism unchanged.

Offline/fast (no container, no vault). The real in-container tool smokes + the
signal->tool routing TRACE live in eval/p37_crypto_trace.py (image-gated), reported
separately — this test only locks the pack's structure so it can't silently rot.
"""
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack  # noqa: E402

DETAILS = ["ecc_dlog.md", "lattice.md", "prng.md", "rsa.md", "sym.md"]


class TestCryptoPack(unittest.TestCase):
    def test_pack_present(self):
        self.assertTrue(skill_pack.has_pack("crypto"))
        self.assertEqual([p.name for p in skill_pack.detail_files("crypto")], DETAILS)

    def test_router_routes_signals_to_tools(self):
        r = skill_pack.router_text("crypto").lower()
        # named specialist tools the image provides
        for tool in ("rsactftool", "fpylll", "sage"):
            self.assertIn(tool, r)
        # factordb must be present AND flagged as network/offline-unavailable
        self.assertIn("factordb", r)
        self.assertTrue("network" in r and ("offline" in r or "--network none" in r))
        # representative signal->technique routes
        for sig in ("fermat", "wiener", "common-modulus", "coppersmith", "pohlig"):
            self.assertIn(sig, r)

    def test_detail_files_cover_conditions_and_tools(self):
        d = {p.name: p.read_text(encoding="utf-8").lower()
             for p in skill_pack.detail_files("crypto")}
        self.assertIn("condition", d["rsa.md"])
        self.assertIn("rsactftool", d["rsa.md"])
        self.assertIn("fpylll", d["lattice.md"])
        self.assertIn("sage", d["ecc_dlog.md"])
        self.assertTrue("mersenne" in d["prng.md"] or "lcg" in d["prng.md"])
        self.assertTrue("ecb" in d["sym.md"] and "padding oracle" in d["sym.md"])

    def test_inject_appends_pack_to_c0_prompt(self):
        base = "BASE_C0_PROMPT"
        c1 = skill_pack.inject(base, "crypto", full=True)
        self.assertTrue(c1.startswith(base))
        self.assertIn("skills/crypto/SKILL.md", c1)
        for name in DETAILS:
            self.assertIn(f"skills/crypto/{name}", c1)
        # router-only is strictly smaller than the full pack (progressive disclosure)
        self.assertLess(len(skill_pack.load_pack("crypto", full=False)),
                        len(skill_pack.load_pack("crypto", full=True)))

    def test_inject_noop_without_pack(self):
        base = "BASE"
        self.assertEqual(skill_pack.inject(base, "no_such_category_xyz"), base)


if __name__ == "__main__":
    unittest.main()
