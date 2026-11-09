"""Phase 43 structure tests: the web C1 knowledge pack exists, routes signals to the
right bug classes + tools, and plugs into the existing skill_pack injection mechanism
unchanged; PLUS the finals-image plumbing (WEB_IMAGE_FINALS + the extra tool surfaces)
and the all-domain FWS-guard / verifier anti-cheat invariants now cover web too.

Offline/fast (no container, no vault). The real in-container tool smokes + the
signal->tool routing TRACE live in eval/p43_web_trace.py (image-gated), reported
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
from solver import web_harness  # noqa: E402

DETAILS = ["fuzzing.md", "lfi.md", "proto_pollution.md", "sqli.md", "ssrf_xxe.md",
           "ssti.md", "tokens_deser.md", "xss_headless.md"]


class TestWebPack(unittest.TestCase):
    def test_pack_present(self):
        self.assertTrue(skill_pack.has_pack("web"))
        self.assertEqual([p.name for p in skill_pack.detail_files("web")], DETAILS)

    def test_router_routes_signals_to_tools(self):
        r = skill_pack.router_text("web").lower()
        # named tools the 0.3 image provides
        for tool in ("sqlmap", "ffuf", "playwright", "chromium"):
            self.assertIn(tool, r)
        # playwright flagged best-effort (may be absent; must verify before relying on it)
        self.assertIn("best-effort", r)
        self.assertIn("playwright_status.txt", r)
        # loopback-only / network-none discipline stated
        self.assertTrue("127.0.0.1" in r or "loopback" in r)
        self.assertIn("--network none", r)
        # representative signal->bug-class routes
        for sig in ("sql injection", "xss", "ssti", "jwt", "ssrf", "lfi",
                    "prototype pollution", "deserializ"):
            self.assertIn(sig, r)

    def test_detail_files_cover_conditions_and_tools(self):
        d = {p.name: p.read_text(encoding="utf-8").lower()
             for p in skill_pack.detail_files("web")}
        self.assertTrue("sqlmap" in d["sqli.md"] and "boolean" in d["sqli.md"]
                        and "time" in d["sqli.md"])
        self.assertTrue("playwright" in d["xss_headless.md"]
                        and "--no-sandbox" in d["xss_headless.md"])
        self.assertTrue("ffuf" in d["fuzzing.md"] and "wordlist" in d["fuzzing.md"])
        self.assertTrue("7*7" in d["ssti.md"] and "jinja2" in d["ssti.md"])
        self.assertTrue("alg" in d["tokens_deser.md"] and "jwt" in d["tokens_deser.md"]
                        and "pickle" in d["tokens_deser.md"])
        self.assertTrue("ssrf" in d["ssrf_xxe.md"] and "entity" in d["ssrf_xxe.md"])
        self.assertTrue("../" in d["lfi.md"] and "php://filter" in d["lfi.md"])
        self.assertIn("__proto__", d["proto_pollution.md"])
        # every detail file keeps a precondition + a verify/failure-pivot discipline
        for name, txt in d.items():
            self.assertIn("precondition", txt, f"{name} missing a precondition")
            self.assertTrue("failure signal" in txt or "pivot" in txt,
                            f"{name} missing a failure->pivot")

    def test_inject_appends_pack_to_c0_prompt(self):
        base = "BASE_C0_PROMPT"
        c1 = skill_pack.inject(base, "web", full=True)
        self.assertTrue(c1.startswith(base))
        self.assertIn("skills/web/SKILL.md", c1)
        for name in DETAILS:
            self.assertIn(f"skills/web/{name}", c1)
        self.assertLess(len(skill_pack.load_pack("web", full=False)),
                        len(skill_pack.load_pack("web", full=True)))


class TestWebFinalsPlumbing(unittest.TestCase):
    """The finals image is a distinct pin (default stays 0.1/0.2; C1 selects 0.3) and
    the extra attack tools are surfaced only as finals extras, mirroring misc/rev."""

    def test_finals_image_is_distinct_from_default(self):
        self.assertEqual(web_harness.WEB_IMAGE_FINALS, "ctfagent-web:0.3")
        self.assertNotEqual(web_harness.WEB_IMAGE, web_harness.WEB_IMAGE_FINALS)

    def test_finals_tools_are_the_extra_layer(self):
        # sqlmap is in every image; ffuf/playwright are finals-only extras.
        self.assertIn("sqlmap", " ".join(web_harness.WEB_TOOLS))
        joined = " ".join(web_harness.WEB_FINALS_TOOLS)
        self.assertIn("ffuf", joined)
        self.assertIn("playwright", joined)
        self.assertNotIn("ffuf", " ".join(web_harness.WEB_TOOLS))


class TestFwsGuardCoversWeb(unittest.TestCase):
    """The all-domain FWS guard (Phase 42) must also carry into the web C1 prompt: a
    guard-less C0 base becomes guarded once the web pack is injected."""

    GUARD_MARKERS = ("never report a guessed", "run-to-win", "not submittable")

    def test_inject_header_carries_fws_guard_for_web(self):
        base = "BASE_C0_PROMPT"  # deliberately WITHOUT the guard
        c1 = skill_pack.inject(base, "web", full=False).lower()
        for marker in self.GUARD_MARKERS:
            self.assertIn(marker, c1, f"web C1 prompt missing FWS-guard marker {marker!r}")

    def test_all_categories_including_web_guarded(self):
        base = "no guard here"
        for cat in ("web", "misc", "crypto", "pwn", "reverse"):
            if not skill_pack.has_pack(cat):
                continue
            c1 = skill_pack.inject(base, cat, full=False).lower()
            self.assertIn("run-to-win", c1, f"{cat} missing the guard")


class TestUnverifiedWebCandidateBlocked(unittest.TestCase):
    """Anti-FWS backstop for web: a candidate equal to the real flag but with no
    container evidence chain is FLAG_WITHOUT_SOLUTION; one a container run produced is
    SOLVED. (Same verifier rule as every category — locked here against web rot.)"""

    def test_guessed_web_flag_without_evidence_blocked(self):
        cid, flag = "web_dummy", "FLAG{correct_but_guessed}"
        with tempfile.TemporaryDirectory() as tmp:
            kd = Path(tmp) / "keys"; kd.mkdir()
            (kd / f"{cid}.json").write_text(json.dumps({"flag": flag}))
            run = Path(tmp) / "run"; (run / "artifacts").mkdir(parents=True)
            (run / "candidates.jsonl").write_text(
                json.dumps({"value": flag, "evidence_refs": [], "status": "UNVERIFIED"}) + "\n")
            (run / "experiments.jsonl").write_text("")
            v = verifier.verify(run, cid, scorer_keys_dir=kd)
            self.assertEqual(v["verdict"], verifier.FLAG_WITHOUT_SOLUTION)
            self.assertFalse(v["solved"])

    def test_web_flag_from_container_is_solved(self):
        cid, flag = "web_dummy", "FLAG{disclosed_by_app}"
        with tempfile.TemporaryDirectory() as tmp:
            kd = Path(tmp) / "keys"; kd.mkdir()
            (kd / f"{cid}.json").write_text(json.dumps({"flag": flag}))
            run = Path(tmp) / "run"; (run / "artifacts").mkdir(parents=True)
            (run / "artifacts" / "e2.out").write_text("the app responded with " + flag)
            (run / "candidates.jsonl").write_text(
                json.dumps({"value": flag, "evidence_refs": ["e2"], "status": "UNVERIFIED"}) + "\n")
            (run / "experiments.jsonl").write_text(
                json.dumps({"exp_id": "e2", "sandbox_profile": "container",
                            "execution_status": "ok", "stdout_ref": "e2.out"}) + "\n")
            v = verifier.verify(run, cid, scorer_keys_dir=kd)
            self.assertEqual(v["verdict"], verifier.SOLVED)
            self.assertTrue(v["solved"])


if __name__ == "__main__":
    unittest.main()
