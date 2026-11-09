"""Phase 38 structure tests: the pwn tool-routing layer (image 0.3 + extended SKILL.md
router + pwn_cli C0/C1 routes). Vault-free and docker-free for the structural checks;
the angr in-container trace is exercised separately by eval/p38_pwn_trace.py.
"""
import importlib
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack  # noqa: E402


class TestPwnRouterExtended(unittest.TestCase):
    def test_skill_md_has_tool_router(self):
        txt = skill_pack.router_text("pwn").lower()
        self.assertIn("tool router", txt)
        # each specialist tool must be named with its signal
        self.assertIn("pwndbg", txt)
        self.assertIn("angr", txt)
        self.assertIn("ropper", txt)
        self.assertIn("one_gadget", txt)

    def test_angr_guarded_and_scoped(self):
        txt = skill_pack.router_text("pwn").lower()
        # angr must carry the state-explosion guard and the "wrong tool for heap" caveat
        self.assertIn("state-explode", txt)
        self.assertIn("wrong tool", txt)
        # the angr API note (angr 10 bundles claripy)
        self.assertIn("angr.claripy", txt)

    def test_pack_injection_carries_tool_router(self):
        c1 = skill_pack.inject("BASE PROMPT", "pwn", full=True)
        self.assertIn("BASE PROMPT", c1)
        self.assertIn("Tool router", c1)          # the new section is injected into C1
        self.assertIn("pwndbg", c1)
        self.assertIn("angr", c1)


class TestPwnCliP38Routing(unittest.TestCase):
    def _reload(self, run_id):
        sys.argv = ["pwn_cli.py", run_id]
        import arena.pwn_cli as m
        importlib.reload(m)
        return m

    def test_c0_route(self):
        m = self._reload("p38c0-r1-xx")
        self.assertEqual(m.pwn_service_harness.PWN_IMAGE, "ctfagent-pwn:0.1")
        self.assertFalse(m.PWNDBG_EXPOSED)
        self.assertFalse(m.ANGR_EXPOSED)
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p38_pwn", "c0"))
        self.assertEqual(m.PWN_BUDGET["max_experiments"], 15)
        # no specialist tools surfaced on C0
        self.assertNotIn("ropper", " ".join(m.PWN_TOOLS))

    def test_c1_route(self):
        m = self._reload("p38c1-r1-xx")
        self.assertEqual(m.pwn_service_harness.PWN_IMAGE, "ctfagent-pwn:0.3")
        self.assertTrue(m.PWNDBG_EXPOSED)
        self.assertTrue(m.ANGR_EXPOSED)
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p38_pwn", "c1"))
        self.assertEqual(m.PWN_BUDGET["max_experiments"], 15)  # identical budget to C0
        joined = " ".join(m.PWN_TOOLS)
        self.assertIn("angr", joined)
        self.assertIn("ropper", joined)

    def test_c0_c1_differ_only_in_knowledge_and_tools(self):
        c0 = self._reload("p38c0-r1-xx")
        b0 = dict(c0.PWN_BUDGET)
        c1 = self._reload("p38c1-r1-xx")
        b1 = dict(c1.PWN_BUDGET)
        self.assertEqual(b0, b1)  # same budget/isolation; only image+pwndbg/angr+pack differ

    def tearDown(self):
        # leave the module in default state for other tests
        sys.argv = ["pwn_cli.py", ""]
        import arena.pwn_cli as m
        importlib.reload(m)


if __name__ == "__main__":
    unittest.main()
