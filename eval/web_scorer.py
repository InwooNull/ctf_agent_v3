"""Phase 19 scorer for the synthetic Web dev set — the ONLY reader of
vault/scorer_keys_web. Same evidence rule as solver/verifier.py: SOLVED needs a
matching candidate AND a container experiment that actually ran (ok|error|timeout)
and printed the flag. Kept separate from the solver path on purpose.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import verifier  # noqa: E402

KEYS_WEB = PROJECT_ROOT / "vault" / "scorer_keys_web"


def score(run_dir, challenge_id):
    return verifier.verify(run_dir, challenge_id, scorer_keys_dir=KEYS_WEB)
