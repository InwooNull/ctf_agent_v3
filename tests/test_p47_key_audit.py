"""Phase 47a: the anti-ghost key-audit queue.

A strong-evidence flag that mismatches the key goes to the key-audit queue (for human key
verification); a guessed flag (no evidence) or a correct flag does not. Blind: the solver
never sees the key — only the orchestrator calls this. Offline, no vault, no live solver.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location("key_audit", PROJECT_ROOT / "eval" / "key_audit.py")
KA = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(KA)

KEY = "flag{correct_key}"


class TestAuditDecision(unittest.TestCase):
    def test_strong_evidence_mismatch_is_queued(self):
        e = KA.audit_run(cid="mr_x", candidate="flag{evidenced_but_wrong}", key_flag=KEY,
                         verdict="UNVERIFIED", has_container_evidence=True)
        self.assertIsNotNone(e)
        self.assertEqual(e["cid"], "mr_x")
        self.assertEqual(e["candidate"], "flag{evidenced_but_wrong}")

    def test_mr_de0abb_realistic_case_is_queued(self):
        # the actual Phase-45/46c situation: evidenced candidate != key
        e = KA.audit_run(cid="mr_de0abb", candidate="flag{e243aae86b6faf93e5ea0d9ab829b71b4efddedf}",
                         key_flag="flag{3b532e0a187006879d262141e16fa5f05f2e6752}",
                         verdict="UNVERIFIED", has_container_evidence=True)
        self.assertIsNotNone(e)

    def test_guessed_flag_without_evidence_is_NOT_queued(self):
        # FWS / no container evidence -> a plain solver failure, not a key-audit case
        self.assertIsNone(KA.audit_run(cid="mr_x", candidate="flag{guess}", key_flag=KEY,
                                       verdict="FLAG_WITHOUT_SOLUTION", has_container_evidence=False))
        self.assertIsNone(KA.audit_run(cid="mr_x", candidate="flag{guess}", key_flag=KEY,
                                       verdict="UNVERIFIED", has_container_evidence=False))

    def test_correct_flag_not_queued(self):
        self.assertIsNone(KA.audit_run(cid="mr_x", candidate=KEY, key_flag=KEY,
                                       verdict="SOLVED", has_container_evidence=True))
        # even if a verdict label were off, an exact key match is never a mismatch
        self.assertIsNone(KA.audit_run(cid="mr_x", candidate=KEY, key_flag=KEY,
                                       verdict="UNVERIFIED", has_container_evidence=True))

    def test_missing_values_not_queued(self):
        self.assertIsNone(KA.audit_run(cid="mr_x", candidate="", key_flag=KEY,
                                       verdict="UNVERIFIED", has_container_evidence=True))


class TestEnqueue(unittest.TestCase):
    def test_enqueue_appends_only_real_entries(self):
        with tempfile.TemporaryDirectory() as t:
            q = Path(t) / "key_audit.jsonl"
            self.assertFalse(KA.enqueue(None, q))          # None -> no write
            self.assertFalse(q.exists())
            e = KA.audit_run(cid="mr_y", candidate="flag{x}", key_flag=KEY,
                             verdict="WRONG_FLAG", has_container_evidence=True)
            self.assertTrue(KA.enqueue(e, q))
            rows = [json.loads(l) for l in q.read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["cid"], "mr_y")


if __name__ == "__main__":
    unittest.main()
