"""Skill-pack / C1 cheatsheet structure tests (deterministic, no LLM).

Validates the pwn C1 pack and the injection mechanism: the router lists techniques and
points only to detail files that exist, the pack is knowledge-only (no ready exploit /
no flag), and inject() turns a C0 prompt into a C1 prompt (and no-ops without a pack).
"""
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import skill_pack  # noqa: E402

EXPECTED_DETAIL = {"heap.md", "glibc_versions.md", "leaks.md", "rop.md"}


class PwnPack(unittest.TestCase):
    def test_pack_present(self):
        self.assertTrue(skill_pack.has_pack("pwn"))
        self.assertFalse(skill_pack.has_pack("no_such_category"))

    def test_router_lists_core_techniques(self):
        t = skill_pack.router_text("pwn").lower()
        for kw in ("tcache", "fsop", "rop", "leak", "glibc"):
            self.assertIn(kw, t, kw)

    def test_router_points_to_existing_detail_files(self):
        names = {p.name for p in skill_pack.detail_files("pwn")}
        self.assertEqual(names, EXPECTED_DETAIL)
        router = skill_pack.router_text("pwn")
        for name in EXPECTED_DETAIL:
            self.assertIn(name, router)  # every detail file is referenced by the router

    def test_version_traps_documented(self):
        glibc = (skill_pack.pack_dir("pwn") / "glibc_versions.md").read_text().lower()
        for marker in ("2.32", "safe-linking", "2.34", "2.29", "tcache"):
            self.assertIn(marker, glibc, marker)

    def test_knowledge_only_no_flag_no_exploit(self):
        full = skill_pack.load_pack("pwn", full=True)
        self.assertNotIn("flag{", full.lower())
        self.assertNotIn("acdc2026{", full.lower())
        # no literal shell-popping payload bytes baked in (knowledge, not an exploit)
        self.assertNotIn("\\x90\\x90", full)

    def test_full_pack_concatenates_details(self):
        router = skill_pack.load_pack("pwn", full=False)
        full = skill_pack.load_pack("pwn", full=True)
        self.assertGreater(len(full), len(router))
        for name in EXPECTED_DETAIL:
            self.assertIn(name, full)


class Injection(unittest.TestCase):
    def test_inject_appends_pack(self):
        base = "You are solving a pwn challenge. Use pwn_cli.py."
        c1 = skill_pack.inject(base, "pwn")
        self.assertTrue(c1.startswith(base))
        self.assertGreater(len(c1), len(base))
        self.assertIn("tcache", c1.lower())

    def test_inject_noop_without_pack(self):
        base = "C0 prompt"
        self.assertEqual(skill_pack.inject(base, "no_such_category"), base)

    def test_c0_vs_c1_differ_only_by_pack(self):
        base = "identical C0 instructions"
        c0 = base
        c1 = skill_pack.inject(base, "pwn")
        self.assertTrue(c1.startswith(c0))             # C1 is C0 + the pack, nothing removed
        self.assertEqual(c1[:len(c0)], c0)


if __name__ == "__main__":
    unittest.main()
