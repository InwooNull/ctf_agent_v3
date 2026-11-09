"""Phase 8 solver-facing CLI for Reverse (C0). Same commands and session/budget
mechanics as eval/c0_cli.py; experiments run in ctfagent-rev:0.1 via RevHarness.

  cd ~/ctf_agent_v3 && python3 arena/rev_cli.py <run_id> info
  cd ~/ctf_agent_v3 && python3 arena/rev_cli.py <run_id> exp <name>  < code.py
  cd ~/ctf_agent_v3 && python3 arena/rev_cli.py <run_id> report <FLAG> <exp_id> [...]
  cd ~/ctf_agent_v3 && python3 arena/rev_cli.py <run_id> give_up <analysis|impl|tool> <reason...>
  cd ~/ctf_agent_v3 && python3 arena/rev_cli.py <run_id> status

Inspect-first is enforced structurally: the first experiment (e01) can never be the
evidence for a report — a flag must come from an experiment written after at least
one observation of the binary.
"""
import importlib.util
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("c0_cli", PROJECT_ROOT / "eval" / "c0_cli.py")
c0_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c0_cli)
from solver.rev_harness import RevHarness  # noqa: E402  (c0_cli put PROJECT_ROOT on sys.path)

REV_BUDGET = {"max_experiments": 8, "wall_s": 900, "exp_timeout_s": 30}
CONTAINER_TOOLS = ["objdump", "readelf", "nm", "strings (binutils)", "gdb", "file", "xxd", "gcc", "python3"]
# Per-route overrides (Phase 40). None => leave the RevHarness/sandbox.json defaults
# (image ctfagent-rev:0.1, memory 256m) untouched for every pre-P40 route.
ANGR_EXPOSED = False
REV_IMAGE_ROUTE = None       # swap the experiment image for this route when set
REV_MEM = None               # raise the container memory limit for this route when set
PERSIST_WORK = False         # persist /work across experiments within a run (Phase 41)
_RUN_ID = next((a for a in sys.argv[1:] if not a.startswith("-")), "")
if _RUN_ID.startswith("p34rv"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p34_rehearsal" / "rev"   # Phase 34 integration rehearsal
elif _RUN_ID.startswith("p36rv"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p36_rev" / "rev"         # Phase 36 real rev holdout (rr_*)
elif _RUN_ID.startswith("p40c0"):
    # Phase 40 C0 baseline: image 0.1, NO angr, NO router pack (injected by the runner).
    # Budget RAISED to 12 exp / 1800 s with a 240 s per-exp cap (VM/CFG lifting is slow),
    # and container memory RAISED to 2g -- IDENTICAL to C1, so the only C0/C1 difference
    # is the angr tool + the knowledge pack. C0 simply has no symbolic tool to spend it on.
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p40_rev" / "c0"
    REV_BUDGET = {"max_experiments": 12, "wall_s": 1800, "exp_timeout_s": 240}
    REV_IMAGE_ROUTE = "ctfagent-rev:0.1"
    REV_MEM = "2g"
elif _RUN_ID.startswith("p40c1"):
    # Phase 40 C1+tools: image 0.2 (angr), router pack injected at spawn by the runner.
    # Identical raised budget 12 exp / 1800 s / 240 s and 2g memory as C0.
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p40_rev" / "c1"
    REV_BUDGET = {"max_experiments": 12, "wall_s": 1800, "exp_timeout_s": 240}
    REV_IMAGE_ROUTE = "ctfagent-rev:0.2"
    REV_MEM = "2g"
    ANGR_EXPOSED = True
elif _RUN_ID.startswith("p41c0"):
    # Phase 41 C0 baseline (fair re-measure): image 0.1, NO angr/pack. Budget RAISED to
    # 20 exp / 3000 s / 300 s-per-exp and /work PERSISTED across experiments -- IDENTICAL
    # to C1 (the only C0/C1 difference stays the angr tool + the knowledge pack).
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p41_rev" / "c0"
    REV_BUDGET = {"max_experiments": 20, "wall_s": 3000, "exp_timeout_s": 300}
    REV_IMAGE_ROUTE = "ctfagent-rev:0.1"
    REV_MEM = "2g"
    PERSIST_WORK = True
elif _RUN_ID.startswith("p41c1"):
    # Phase 41 C1+tools (fair re-measure): image 0.2 (angr) + router pack injected at spawn.
    # Identical raised budget 20 exp / 3000 s / 300 s, 2g, and persisted /work as C0.
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p41_rev" / "c1"
    REV_BUDGET = {"max_experiments": 20, "wall_s": 3000, "exp_timeout_s": 300}
    REV_IMAGE_ROUTE = "ctfagent-rev:0.2"
    REV_MEM = "2g"
    ANGR_EXPOSED = True
    PERSIST_WORK = True
else:
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p8_c0"
c0_cli.C0_BUDGET = REV_BUDGET
c0_cli.CryptoHarness = RevHarness          # open_harness() builds the rev harness
c0_cli.__doc__ = __doc__
CliError = c0_cli.CliError

# Phase 40: switch the experiment image + raise memory per route, without touching the
# RevHarness defaults or config/sandbox.json (which every other lane shares). open_harness
# builds the harness fresh each CLI call; we post-patch the instance it returns.
_orig_open_harness = c0_cli.open_harness


def _open_harness(run_id, sess):
    h = _orig_open_harness(run_id, sess)
    if REV_IMAGE_ROUTE:
        h.image = REV_IMAGE_ROUTE
        h.sandbox_config["container"]["image"] = REV_IMAGE_ROUTE
    if REV_MEM:
        h.sandbox_config["container"]["limits"] = dict(
            h.sandbox_config["container"]["limits"], memory=REV_MEM)
    if PERSIST_WORK:
        h.persist_work = True
    return h


c0_cli.open_harness = _open_harness


def cmd_info(run_id, sess, args):
    d = Path(sess["challenge_dir"])
    ch = json.loads((d / "challenge.json").read_text())
    files = [{"name": f, "size": (d / f).stat().st_size, "container_path": f"/input/{f}"}
             for f in ch.get("files", [])]
    tools = CONTAINER_TOOLS + (["angr (symbolic exec; import angr -> angr.claripy)"] if ANGR_EXPOSED else [])
    angr_hint = (" angr is available for VM/bytecode, CFG-flattening and many-constraint "
                 "crackmes (import angr; claripy = angr.claripy). GUARD it first: bound the "
                 "symbolic input, give BOTH find and avoid addresses, cap the step count and "
                 "use Veritesting -- it state-explodes on big VM/flattened binaries otherwise, "
                 "and it is the WRONG tool for a tiny or single-xor check (invert that by hand). "
                 "Set HOME=/work so it can write its cache (root FS is read-only)."
                 if ANGR_EXPOSED else "")
    print(json.dumps({
        "category": ch["category"], "difficulty": ch.get("difficulty"), "description": ch["description"],
        "flag_format": ch.get("flag_format"), "files": files, "budget": REV_BUDGET,
        "remaining": c0_cli._remaining(sess), "container_tools": tools,
        "angr": "available" if ANGR_EXPOSED else "NOT installed",
        "work_persists": PERSIST_WORK,
        "how": "files are only readable inside experiments, at /input/<name> (read-only). An experiment is "
               "python3 code; call the tools via subprocess. Writable cwd is /work (root FS is read-only: "
               "use /work for scratch files, e.g. TMPDIR=/work)." +
               (" /work PERSISTS across your experiments in this run: files you unpack/build/write "
                "(unzipped sources, a Python emulator, an angr script) stay for the next experiment -- "
                "build your harness ONCE and reuse it, don't redo setup every experiment." if PERSIST_WORK else "") +
               angr_hint + " Experiment e01 cannot be cited as evidence."},
        indent=2))


def cmd_report(run_id, sess, args):
    prefix = sess["challenge_id"] + "-"
    refs = [r if r.startswith(prefix) else prefix + r for r in args[1:]]
    if refs and all(r[len(prefix):].startswith("e01_") for r in refs):
        raise CliError("inspect-first: the first experiment (e01) cannot be the evidence; "
                       "cite a later experiment that printed the flag")
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
