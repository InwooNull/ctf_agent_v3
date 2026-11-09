"""Phase 10 solver-facing CLI for the real (NYU CTF Bench) Reverse holdout — C0.
Same commands / session / budget mechanics as arena/rev_cli.py; only the budget, the run
store and the info text differ.

  cd ~/ctf_agent_v3 && python3 arena/real_cli.py <run_id> info|exp <name>|report <FLAG> <exp_id>...|give_up <analysis|impl|tool> <reason>|status
"""
import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("rev_cli", PROJECT_ROOT / "arena" / "rev_cli.py")
rev_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rev_cli)
c0_cli = rev_cli.c0_cli

REAL_BUDGET = {"max_experiments": 10, "wall_s": 1200, "exp_timeout_s": 60}
c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p10_c0"
c0_cli.C0_BUDGET = REAL_BUDGET
c0_cli.__doc__ = __doc__


def cmd_info(run_id, sess, args):
    d = Path(sess["challenge_dir"])
    ch = json.loads((d / "challenge.json").read_text())
    files = [{"name": f, "size": (d / f).stat().st_size, "container_path": f"/input/{f}"} for f in ch["files"]]
    print(json.dumps({
        "category": ch["category"], "title": ch["title"], "description": ch["description"],
        "flag_format": ch.get("flag_format"), "files": files, "budget": REAL_BUDGET,
        "remaining": c0_cli._remaining(sess), "container_tools": rev_cli.CONTAINER_TOOLS,
        "how": "files are only readable inside experiments, at /input/<name> (read-only, shipped without the "
               "exec bit: copy a binary to /work and chmod +x it before running it). An experiment is python3 "
               "code; call the tools via subprocess. Writable cwd is /work (root FS is read-only: use /work for "
               "scratch files, e.g. TMPDIR=/work). No network. Experiment e01 cannot be cited as evidence."},
        indent=2))


c0_cli.COMMANDS["info"] = cmd_info

if __name__ == "__main__":
    sys.exit(c0_cli.main(sys.argv[1:]))
