"""Phase 22 solver-facing CLI for Misc/Forensics (C0), on a plain --network none
container (no 2-uid service boundary — all work is on LOCAL challenge files).

  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py <run_id> info
  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py <run_id> exp <name>   < code.py
  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py <run_id> report <FLAG> <exp_id> [...]
  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py <run_id> give_up <analysis|impl|tool> <reason...>
  cd ~/ctf_agent_v3 && python3 arena/misc_cli.py <run_id> status

Each `exp` runs your python as `python3 -I /work/<name>.py` inside ONE container
(--network none, read-only root, non-root, cap-drop ALL). The challenge files
are mounted read-only at /input/<name>; writable scratch (carving, TMPDIR) is
/work. Your python may subprocess the image tools (file/binwalk/exiftool/
steghide/foremost/outguess/tshark/tcpdump/pdftotext/convert/xxd/strings/zsteg)
or import pillow/numpy/pyzbar.

Inspect first: observe the file(s) (file/binwalk/exiftool/xxd/strings) to work
out the type BEFORE writing a whole extraction script. e01 can never be cited
as the evidence experiment — cite a later experiment that actually printed the
flag from the challenge data.
"""
import importlib.util
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("c0_cli", PROJECT_ROOT / "eval" / "c0_cli.py")
c0_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c0_cli)
from solver.misc_harness import (MiscHarness, MISC_TOOLS, MISC_PYLIBS, agent_scratch_dir,  # noqa: E402
                                  MISC_FINALS_TOOLS, MISC_WORDLIST, MISC_IMAGE_FINALS)

# Route store/budget by run_id prefix (one CLI can serve several misc configs).
#   p22c0-* : Misc/Forensics C0 x1 baseline -> store/p22_misc, budget 12 exps / 1200 s / 90 s-per-exp
_RUN_ID = next((a for a in sys.argv[1:] if not a.startswith("-")), "")
MISC_IMG = "ctfagent-misc:0.1"              # prior phases pinned 0.1; finals (p36) uses 0.2 (p7zip)
if _RUN_ID.startswith("p22c0"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p22_misc"
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
elif _RUN_ID.startswith("p34c0"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p34_rehearsal" / "misc"   # Phase 34 integration rehearsal
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
elif _RUN_ID.startswith("p36ms"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p36_misc" / "misc"        # Phase 36 real misc holdout (mr_*)
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
    MISC_IMG = "ctfagent-misc:0.2"
elif _RUN_ID.startswith("p50t"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p45_misc"                 # Phase 50 budget lever: per-exp 180s
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 1800, "exp_timeout_s": 180}
    MISC_IMG = "ctfagent-misc:0.5"
elif _RUN_ID.startswith("p51c1") or _RUN_ID.startswith("p51c2"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p51_misc"                 # Phase 51 growth cycle (mr_*), isolated store
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
    MISC_IMG = "ctfagent-misc:0.5"                                       # finals image (0.5: +OCR/cv2/stegseek) + skills/misc pack (C1)
elif _RUN_ID.startswith("p52c2"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p52_misc"                 # Phase 52 cycle 2 re-measure (mr_*), isolated store
    # max_experiments stays 12 (the budget LEVER was gate-rolled-back in cycle 1). The
    # HARNESS fixes under test are: ctfagent-misc:0.6 (+pycryptodome), crack-class per-exp
    # timeout 90->300 (stegseek/john sweeps), /work persistence + pids 512 (set in
    # solver/misc_harness.py). Isolation profile (config/sandbox.json) is UNCHANGED.
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 2400, "exp_timeout_s": 300}
    MISC_IMG = "ctfagent-misc:0.6"
    os.environ["MISC_PERSIST_WORK"] = "1"   # Phase 52: persist /work across experiments for this route
elif _RUN_ID.startswith("p45ms") or _RUN_ID.startswith("p48"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p45_misc"                 # Phase 45/48 growth (mr_*)
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
    MISC_IMG = "ctfagent-misc:0.5"                                       # finals image (0.5: +OCR/cv2/stegseek) + skills/misc pack (C1)
else:
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p22_misc"
    MISC_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
c0_cli.C0_BUDGET = MISC_BUDGET
import functools as _ft                      # bind the image so open_harness builds the right one
c0_cli.CryptoHarness = _ft.partial(MiscHarness, image=MISC_IMG)   # open_harness builds a MiscHarness (misc image)
c0_cli.__doc__ = __doc__
CliError = c0_cli.CliError

TOOLS = list(MISC_TOOLS) + [f"python3 (import {lib})" for lib in MISC_PYLIBS]


def cmd_info(run_id, sess, args):
    import json
    ch = json.loads((Path(sess["challenge_dir"]) / "challenge.json").read_text())
    files = [{"name": f, "size": (Path(sess["challenge_dir"]) / f).stat().st_size,
              "container_path": f"/input/{f}"} for f in ch.get("files", [])]
    scratch = str(agent_scratch_dir(c0_cli.C0_ROOT, run_id))
    _finals = (MISC_IMG == MISC_IMAGE_FINALS)
    print(json.dumps({
        "title": ch["title"], "category": ch["category"], "description": ch["description"],
        "flag_format": ch.get("flag_format"), "files": files,
        "budget": MISC_BUDGET, "remaining": c0_cli._remaining(sess), "tools": TOOLS,
        **({"specialist_tools": list(MISC_FINALS_TOOLS),
            "wordlist": MISC_WORDLIST} if _finals else {}),
        "scratch_dir": scratch,
        "scratch_note": ("write your experiment code file HERE (unique to this run) and redirect it "
                         "into `exp`, e.g. `exp e02_try < " + scratch + "/code.py`. Do NOT use a shared "
                         "path in the repo root — parallel runs would clobber it."),
        "how": "each `exp` is python3 -I run in a --network none container; challenge files are "
               "read-only at /input/<name>, writable scratch is /work (set TMPDIR=/work, carve into "
               "/work). Subprocess the tools or import pillow/numpy/pyzbar. Observe the file type "
               "first (file/binwalk/exiftool/xxd/strings) before writing a full extractor. To finish: "
               "`report <FLAG> <exp_id>` citing the experiment whose stdout printed the flag "
               "(e01 cannot be cited)."},
        indent=2))


def cmd_report(run_id, sess, args):
    prefix = sess["challenge_id"] + "-"
    refs = [r if r.startswith(prefix) else prefix + r for r in args[1:]]
    if refs and all(r[len(prefix):].startswith("e01_") for r in refs):
        raise CliError("inspect-first: e01 cannot be the evidence; cite a later experiment that "
                       "printed the flag from the challenge data")
    return _orig_report(run_id, sess, args)


def cmd_give_up(run_id, sess, args):
    if len(args) < 2 or args[0] not in ("analysis", "impl", "tool"):
        raise CliError("usage: give_up <analysis|impl|tool> <reason...>")
    sess["status"] = "GIVE_UP"
    sess["give_up"] = {"kind": args[0], "reason": " ".join(args[1:])}
    sess["ended_at"] = time.time()
    c0_cli.save_session(run_id, sess)
    print("give-up recorded; session closed.")


_orig_report = c0_cli.COMMANDS["report"]
c0_cli.COMMANDS.update({"info": cmd_info, "report": cmd_report, "give_up": cmd_give_up})

if __name__ == "__main__":
    sys.exit(c0_cli.main(sys.argv[1:]))
