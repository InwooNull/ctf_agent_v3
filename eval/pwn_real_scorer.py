"""Scorer for the real (NYU) pwn problems — the ONLY reader of vault/scorer_keys_pwn_real.
Same evidence rule as solver/verifier.py (matching candidate AND a container experiment that ran and
printed the flag)."""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import verifier  # noqa: E402

KEYS = PROJECT_ROOT / "vault" / "scorer_keys_pwn_real"


def score(run_dir, challenge_id):
    return verifier.verify(run_dir, challenge_id, scorer_keys_dir=KEYS)
