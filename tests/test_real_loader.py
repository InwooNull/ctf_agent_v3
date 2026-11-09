"""Phase 9: eval/real_loader.py routes bench files into the blind layout (fake bench dir; no vault)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
import real_loader  # noqa: E402

FLAG = "csawctf{fake_test_flag_123}"


class RealLoaderTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        t = Path(self.t.name)
        self.src = t / "bench" / "chal"
        (self.src / "chal").mkdir(parents=True)
        (self.src / "chal" / "crackme").write_bytes(b"\x7fELF fake binary")
        (self.src / "solver.py").write_text(f"print('{FLAG}')\n")
        (self.src / "flag.txt").write_text(FLAG)
        (self.src / "challenge.json").write_text(json.dumps({
            "name": "crackme", "category": "rev", "author": "Someone", "flag": FLAG, "points": 100,
            "reference": "https://example.invalid/writeup",
            "description": "Find the password.\n\nAuthor: Someone\n", "files": ["./chal/crackme"]}))
        self.arena, self.vault = t / "arena", t / "vault"
        self.rec = real_loader.load_one(self.src, "rr_abcdef", "holdout", "2099q-rev-crackme",
                                        {"year": "2099", "event": "X", "challenge": "crackme", "path": "p"},
                                        arena=self.arena, vault=self.vault)

    def test_public_has_only_listed_files_and_sanitized_json(self):
        pub = self.arena / "rr_abcdef"
        self.assertEqual(sorted(p.name for p in pub.iterdir()), ["challenge.json", "crackme"])
        ch = json.loads((pub / "challenge.json").read_text())
        self.assertEqual(set(ch), set(real_loader.PUBLIC_KEYS))
        blob = json.dumps(ch)
        for secret in (FLAG, "Someone", "example.invalid", "points"):
            self.assertNotIn(secret, blob)
        self.assertEqual(ch["flag_format"], "csawctf{...}")
        self.assertEqual(ch["description"], "Find the password.")

    def test_secrets_routed_to_vault(self):
        key = json.loads((self.vault / "scorer_keys_real" / "rr_abcdef.json").read_text())
        self.assertEqual(key["flag"], FLAG)
        wu = self.vault / "writeups_real" / "rr_abcdef"
        self.assertTrue((wu / "files" / "solver.py").exists())
        self.assertTrue((wu / "files" / "flag.txt").exists())
        self.assertIn("example.invalid", (wu / "reference.json").read_text())
        self.assertEqual(sorted(self.rec["withheld_files"]), ["challenge.json", "flag.txt", "solver.py"])

    def test_missing_listed_file_rejected(self):
        c = json.loads((self.src / "challenge.json").read_text())
        c["files"] = ["nope.bin"]
        (self.src / "challenge.json").write_text(json.dumps(c))
        with self.assertRaises(FileNotFoundError):
            real_loader.load_one(self.src, "rr_000000", "dev", "x", {"year": "", "event": "", "challenge": "", "path": ""},
                                 arena=self.arena, vault=self.vault)


if __name__ == "__main__":
    unittest.main()
