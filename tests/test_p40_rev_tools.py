"""Phase 40 tests: the reverse router pack, the ctfagent-rev:0.2 angr image wiring, and the
p40 C0/C1 CLI routing. Structural checks are docker-free; the angr end-to-end proof
(and C0-has-no-angr) is gated on docker + the images.
"""
import importlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack            # noqa: E402
from solver.rev_harness import RevHarness       # noqa: E402
from tools import sandbox                        # noqa: E402

IMG02 = "ctfagent-rev:0.2"
IMG01 = "ctfagent-rev:0.1"


class TestReverseRouterPack(unittest.TestCase):
    def test_pack_present_and_loadable(self):
        self.assertTrue(skill_pack.has_pack("reverse"))
        router = skill_pack.router_text("reverse")
        # the four signal->tool routes the phase measures
        for sig in ("VM / bytecode interpreter", "control-flow flattening",
                    "constraint / crackme", "anti-debug", "stripped"):
            self.assertIn(sig, router, sig)
        # angr is named as the tool, and the guard comes FIRST
        self.assertIn("angr", router.lower())
        self.assertIn("guard it FIRST", router)
        self.assertIn("state-explode", router)

    def test_detail_files_cover_each_route(self):
        names = {p.name for p in skill_pack.detail_files("reverse")}
        self.assertEqual(names, {"vm.md", "cfg_flatten.md", "constraints.md",
                                 "antidebug.md", "stripped.md"})

    def test_pack_names_no_challenge(self):
        full = skill_pack.load_pack("reverse", full=True)
        for cid in ("halfpike", "parallel vm", "steady_counting", "brrr",
                    "rr_1b3102", "rr_df0262", "rr_96228d", "rr_85d2f8"):
            self.assertNotIn(cid, full)


class TestImageDockerfile(unittest.TestCase):
    def test_dockerfile_pins_angr_and_shims(self):
        src = (PROJECT_ROOT / "docker" / "Dockerfile.rev02").read_text()
        self.assertIn("FROM ctfagent-rev:0.1", src)
        self.assertIn("angr==10.0.5", src)
        self.assertIn("sitecustomize.py", src)       # getpwuid + HOME/TMPDIR shim
        self.assertIn("getpwuid", src)
        self.assertIn("radare2", src)                # the omission is recorded

    def test_rev02_versions_recorded(self):
        rec = (PROJECT_ROOT / "docker" / "rev02_versions.txt").read_text()
        self.assertIn("angr=10.0.5", rec)
        # the 0.1 record (pinned by test_rev_pipeline) must stay angr-free
        self.assertNotIn("angr", (PROJECT_ROOT / "docker" / "rev_versions.txt").read_text())


class TestP40Routing(unittest.TestCase):
    def _load(self, run_id):
        sys.argv = ["rev_cli.py", run_id, "status"]
        spec = importlib.util.spec_from_file_location("rev_cli_probe", PROJECT_ROOT / "arena" / "rev_cli.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_c0_route(self):
        m = self._load("p40c0-r1-rr_df0262")
        self.assertEqual(m.REV_IMAGE_ROUTE, IMG01)
        self.assertFalse(m.ANGR_EXPOSED)
        self.assertEqual(m.REV_MEM, "2g")
        self.assertEqual(m.REV_BUDGET, {"max_experiments": 12, "wall_s": 1800, "exp_timeout_s": 240})
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p40_rev", "c0"))

    def test_c1_route(self):
        m = self._load("p40c1-r1-rr_df0262")
        self.assertEqual(m.REV_IMAGE_ROUTE, IMG02)
        self.assertTrue(m.ANGR_EXPOSED)
        self.assertEqual(m.REV_MEM, "2g")
        self.assertEqual(m.c0_cli.C0_ROOT.parts[-2:], ("p40_rev", "c1"))

    def test_c0_c1_same_budget(self):
        b0 = self._load("p40c0-r1-rr_df0262").REV_BUDGET
        b1 = self._load("p40c1-r1-rr_df0262").REV_BUDGET
        self.assertEqual(b0, b1)

    def test_pre_p40_routes_untouched(self):
        m = self._load("p36rv-r1-rr_df0262")
        self.assertIsNone(m.REV_IMAGE_ROUTE)      # default image 0.1 via RevHarness
        self.assertIsNone(m.REV_MEM)              # default sandbox.json memory
        self.assertFalse(m.ANGR_EXPOSED)
        self.assertEqual(m.REV_BUDGET["max_experiments"], 8)

    def tearDown(self):
        sys.argv = ["rev_cli.py", ""]


@unittest.skipUnless(sandbox.docker_available() and sandbox.image_available(IMG02),
                     f"{IMG02} / docker not available")
class TestAngrRunsOnImage02(unittest.TestCase):
    CODE = ("import os\n"
            "try:\n"
            "    import angr; c=angr.claripy; s=c.Solver(); x=c.BVS('x',32); s.add(x*3==111)\n"
            "    print('ANGR_OK', angr.__version__, s.eval(x,1)[0])\n"
            "except Exception as e:\n"
            "    print('NO_ANGR', type(e).__name__)\n")

    def _run(self, image):
        tmp = tempfile.mkdtemp()
        h = RevHarness("t", str(PROJECT_ROOT / "arena" / "real_rev" / "rr_df0262"),
                       store_root=tmp, image=image, budget={"time_s": 300, "max_attempts": 3})
        h.sandbox_config["container"]["limits"] = dict(
            h.sandbox_config["container"]["limits"], memory="2g")
        return h.run_experiment({"name": "e01_probe", "code": self.CODE, "timeout": 120})

    def test_angr_imports_and_solves_under_sandbox(self):
        o = self._run(IMG02)
        self.assertEqual(o.execution_status, "ok", o.stdout)
        self.assertIn("ANGR_OK 10.0.5 37", o.stdout)   # shim handles passwd + read-only root


@unittest.skipUnless(sandbox.docker_available() and sandbox.image_available(IMG01),
                     f"{IMG01} / docker not available")
class TestC0HasNoAngr(TestAngrRunsOnImage02):
    def test_angr_imports_and_solves_under_sandbox(self):
        o = self._run(IMG01)
        self.assertEqual(o.execution_status, "ok", o.stdout)
        self.assertIn("NO_ANGR ModuleNotFoundError", o.stdout)  # C0 arm: angr absent


class TestTraceArtifact(unittest.TestCase):
    def test_trace_json_proves_angr_solved_a_vm(self):
        p = PROJECT_ROOT / "store" / "p40_rev" / "trace.json"
        if not p.exists():
            self.skipTest("trace not generated (run eval/p40_rev_trace.py)")
        t = json.loads(p.read_text())
        self.assertTrue(t["routed"])
        self.assertTrue(t["tool_ran"])
        self.assertTrue(t["result_ok"])
        self.assertTrue(t["step"]["binary_confirms_win"])


if __name__ == "__main__":
    unittest.main()
