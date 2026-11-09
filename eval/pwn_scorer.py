"""Scorer for the synthetic pwn dev set — the ONLY reader of vault/scorer_keys_pwn.
Same evidence rule as solver/verifier.py: SOLVED needs a matching candidate AND a
container experiment that actually ran (ok|error|timeout) and printed the flag.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import verifier  # noqa: E402

KEYS_PWN = PROJECT_ROOT / "vault" / "scorer_keys_pwn"


def score(run_dir, challenge_id):
    return verifier.verify(run_dir, challenge_id, scorer_keys_dir=KEYS_PWN)
