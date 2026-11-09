"""Phase 51 — deterministic (cost-0) tests for the misc experience lever.

Covers: promotion draws ONLY from non-FWS successes, is append+dedup, stores NO flag,
round-trips via load(); render_injection produces flag-free injectable text; and the
rendered experience.md is actually picked up by skill_pack.load_pack (the injection path).
"""
import json
import tempfile
import unittest
from pathlib import Path

from growth.loop import RunOutcome
from growth.diagnoser import promotable_successes
from growth import experience as X


def _run(cid, solved, fws=False, excerpt="", subtype="forensics", category="forensics",
         winning_exp=""):
    sig = {"transcript_excerpt": excerpt, "fws": fws, "winning_exp": winning_exp}
    r = RunOutcome(cid=cid, outcome=("SOLVED" if solved else "GIVE_UP"), solved=solved,
                   category=category, signals=sig)
    r.subtype = subtype
    r.winning_exp = winning_exp
    return r


class TestExperienceLever(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()) / "experience_misc.jsonl"

    def _promote(self, runs):
        successes = promotable_successes(runs)
        recs = [X.build_record(r, transcript_text=r.signals.get("transcript_excerpt", ""))
                for r in successes]
        return X.promote(recs, store_path=self.tmp)

    def test_fws_never_promoted(self):
        runs = [
            _run("c_ok", True, excerpt="ran zsteg -a image.png; flag printed", winning_exp="c_ok-e03"),
            _run("c_fws", True, fws=True, excerpt="binwalk carve; flag theme-matched"),  # solved+fws
            _run("c_fail", False, excerpt="gave up"),
        ]
        written = self._promote(runs)
        subtypes = {r["subtype"] for r in written}
        cids = {r["source"].split()[0] for r in written}
        self.assertIn("c_ok", cids)
        self.assertNotIn("c_fws", cids)          # FWS excluded at the source
        self.assertEqual(len(written), 1)

    def test_no_flag_stored(self):
        runs = [_run("c1", True, excerpt="steghide extract -sf a.bmp; FLAG{should_not_persist}",
                     winning_exp="c1-e02")]
        self._promote(runs)
        blob = self.tmp.read_text()
        self.assertNotIn("FLAG{should_not_persist}", blob)
        self.assertNotIn("flag{", blob.lower())
        for rec in X.load((self.tmp,)):
            self.assertTrue(rec["no_flag"])

    def test_append_and_dedup(self):
        r1 = [_run("c1", True, excerpt="zsteg lsb", subtype="forensics", winning_exp="c1-e02")]
        n1 = self._promote(r1)
        self.assertEqual(len(n1), 1)
        # same subtype + same technique fingerprint -> deduped, nothing new appended
        r2 = [_run("c2", True, excerpt="zsteg lsb again", subtype="forensics", winning_exp="c2-e01")]
        n2 = self._promote(r2)
        self.assertEqual(len(n2), 0)
        # different technique -> new record
        r3 = [_run("c3", True, excerpt="tshark follow tcp; strings", subtype="forensics",
                   winning_exp="c3-e04")]
        n3 = self._promote(r3)
        self.assertEqual(len(n3), 1)
        self.assertEqual(len(X.load((self.tmp,))), 2)

    def test_header_written_once(self):
        self._promote([_run("c1", True, excerpt="exiftool", winning_exp="c1-e02")])
        first = self.tmp.read_text().splitlines()[0]
        self.assertEqual(json.loads(first)["schema"], "misc-solve-pattern/v1")
        self._promote([_run("c2", True, excerpt="foremost carve zip", winning_exp="c2-e02")])
        headers = [l for l in self.tmp.read_text().splitlines() if '"schema"' in l]
        self.assertEqual(len(headers), 1)         # schema header exactly once

    def test_render_injection_flag_free_and_lists(self):
        patterns = [
            {"subtype": "forensics", "category": "forensics", "technique": ["zsteg", "PIL"],
             "recipe": "triage each image, zsteg -a the odd-one-out carrier", "signals": "flag printed",
             "confidence": "verified", "no_flag": True},
            {"subtype": "misc", "category": "misc", "technique": ["base64", "xxd"],
             "recipe": "peel nested encodings", "signals": "flag printed", "confidence": "verified",
             "no_flag": True},
        ]
        md = X.render_injection(patterns)
        self.assertIn("zsteg", md)
        self.assertIn("base64", md)
        self.assertNotIn("flag{", md.lower())
        self.assertNotIn("FLAG{", md)

    def test_injection_reaches_skill_pack(self):
        """experience.md rendered into skills/misc/ is concatenated by load_pack(full=True)."""
        from orchestrator import skill_pack
        target = X.INJECTION_FILE
        self.assertFalse(target.exists(), "test expects no pre-existing experience.md")
        try:
            target.write_text(X.render_injection(
                [{"subtype": "forensics", "category": "forensics", "technique": ["zsteg"],
                  "recipe": "zsteg the carrier", "signals": "flag printed", "confidence": "verified",
                  "no_flag": True}]))
            pack = skill_pack.load_pack("misc", full=True)
            self.assertIn("experience.md", pack)
            self.assertIn("zsteg the carrier", pack)
        finally:
            if target.exists():
                target.unlink()


if __name__ == "__main__":
    unittest.main()
