"""Phase 6 solver-facing CLI (one-shot). Same commands and behaviour as
eval/c0_cli.py; only the budget (1 container experiment) and the run store differ.
C0 and C1 sessions use this same CLI — the configs differ only in the prompt.

  cd ~/ctf_agent_v3 && python3 arena/p6_cli.py <run_id> <subcommand> ...
  run ids p6c0-... -> store/p6_c0 ; p6c1-... -> store/p6_c1
"""
import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("c0_cli", PROJECT_ROOT / "eval" / "c0_cli.py")
c0_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c0_cli)

P6_BUDGET = {"max_experiments": 1, "wall_s": 1200, "exp_timeout_s": 30}
_rid = sys.argv[1] if len(sys.argv) > 1 else ""
c0_cli.C0_ROOT = PROJECT_ROOT / "store" / ("p6_c1" if _rid.startswith("p6c1-") else "p6_c0")
c0_cli.C0_BUDGET = P6_BUDGET
c0_cli.__doc__ = __doc__

if __name__ == "__main__":
    sys.exit(c0_cli.main(sys.argv[1:]))
