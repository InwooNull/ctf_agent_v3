"""Phase 5b solver-facing CLI. Same commands, budget and behaviour as
eval/c0_cli.py (info / exp / report / give_up / status); only the run store
differs (store/c0b/<run_id>/).

  cd ~/ctf_agent_v3 && python3 arena/c0b_cli.py <run_id> <subcommand> ...
"""
import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("c0_cli", PROJECT_ROOT / "eval" / "c0_cli.py")
c0_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c0_cli)
# run ids c0b-... -> store/c0b (set v1), c0b2-... -> store/c0b2 (set v2)
c0_cli.C0_ROOT = PROJECT_ROOT / "store" / ("c0b2" if sys.argv[1:2] and sys.argv[1].startswith("c0b2-") else "c0b")
c0_cli.__doc__ = __doc__

if __name__ == "__main__":
    sys.exit(c0_cli.main(sys.argv[1:]))
