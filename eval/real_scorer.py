"""Phase 9 scorer for the real (NYU CTF Bench) Reverse problems — the ONLY reader of
vault/scorer_keys_real. Same evidence rule as solver/verifier.py: SOLVED needs a matching
candidate AND a container experiment that actually ran (ok|error|timeout) and printed it.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import verifier  # noqa: E402

KEYS_REAL = PROJECT_ROOT / "vault" / "scorer_keys_real"


def score(run_dir, challenge_id):
    return verifier.verify(run_dir, challenge_id, scorer_keys_dir=KEYS_REAL)
