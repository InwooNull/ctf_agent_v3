"""Phase 14 solver-facing CLI for Pwn (C0), on the 2-uid pwn-service boundary.

  cd ~/ctf_agent_v3 && python3 arena/pwn_cli.py <run_id> info
  cd ~/ctf_agent_v3 && python3 arena/pwn_cli.py <run_id> exp <name>   < code.py
  cd ~/ctf_agent_v3 && python3 arena/pwn_cli.py <run_id> report <FLAG> <exp_id> [...]
  cd ~/ctf_agent_v3 && python3 arena/pwn_cli.py <run_id> give_up <analysis|impl|tool> <reason...>
  cd ~/ctf_agent_v3 && python3 arena/pwn_cli.py <run_id> status

Each `exp` runs your python as the AGENT uid inside one --network none container. The vulnerable binary
is public at /input/<name> (analyze it with file/checksec/objdump/readelf/nm/gdb/pwntools/ROPgadget/
one_gadget). The LIVE target that holds the flag runs as a different uid behind a loopback service; you
reach it ONLY via a tube to 127.0.0.1:$PORT. flag.txt is readable only by the service uid, so the flag
comes only from actually exploiting the service. Inspect first: e01 can never be cited as evidence.
"""
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("c0_cli", PROJECT_ROOT / "eval" / "c0_cli.py")
c0_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c0_cli)
from solver import pwn_service_harness  # noqa: E402
from solver.pwn_service_harness import PwnServiceHarness  # noqa: E402
from tools import pwn_service  # noqa: E402

TOOLS = ["file", "checksec (pwntools)", "objdump", "readelf", "nm", "gdb (batch, -nx)", "python3",
         "pwntools", "ROPgadget", "one_gadget"]

# Route store/image/pwndbg-exposure/budget by run_id prefix so one CLI serves several configs.
#  p16ac0-* : clean C0 baseline  -> store p16a_c0, image 0.1, pwndbg-free, budget 15/1800 (Phase 16a)
#  p16bc0-* : budget-lever probe -> store p16b_c0, image 0.1, pwndbg-free, budget 30/3600 (Phase 16b)
#  p23a-*   : C3a budget++ probe  -> store p23_pwn/c3a, image 0.1, pwndbg-free, budget 30/3600 (Phase 23)
#  p23b-*   : C3b multi-attempt   -> store p23_pwn/c3b, image 0.1, pwndbg-free, budget 15/1800 (Phase 23)
#  p23d-*   : Cpwndbg tool probe  -> store p23_pwn/cpwndbg, image 0.2, pwndbg EXPOSED, budget 15/1800 (Phase 23)
#  default  : Phase 14 recon     -> store p14_c0, image 0.2, pwndbg exposed
_RUN_ID = next((a for a in sys.argv[1:] if not a.startswith("-")), "")
ANGR_EXPOSED = False   # only the C1+tools route turns this on (reload-safe default)
if _RUN_ID.startswith("p16ac0"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p16a_c0"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p23a"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p23_pwn" / "c3a"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 30, "wall_s": 3600, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p23b"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p23_pwn" / "c3b"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p23d"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p23_pwn" / "cpwndbg"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.2"
    PWNDBG_EXPOSED = True
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p31c0"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p31_pwn" / "c0"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p31c1"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p31_pwn" / "c1"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p34pw"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p34_rehearsal" / "pwn"   # Phase 34 integration rehearsal
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p36pw"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p36_pwn_b1" / "pwn"      # Phase 36 real-holdout baseline (batch 1)
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p38c0"):
    # Phase 38 C0 baseline: no cheatsheet, no specialist tools, pwndbg-free (image 0.1).
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p38_pwn" / "c0"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p38c1"):
    # Phase 38 C1+tools: cheatsheet (injected in the spawn prompt) + specialist tools
    # exposed -- pwndbg + angr + ropper on image 0.3. Same budget/isolation as C0; the
    # only differences are the knowledge pack and the tool image.
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p38_pwn" / "c1"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.3"
    PWNDBG_EXPOSED = True
    ANGR_EXPOSED = True
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p39c0"):
    # Phase 39 C0 baseline (fair re-measure): no cheatsheet/tools, pwndbg-free (image 0.1),
    # heap budget RAISED to 30 exp / 3600 s (same as C1).
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p39_pwn" / "c0"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 30, "wall_s": 3600, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p39c1"):
    # Phase 39 C1+tools (fair re-measure): cheatsheet + pwndbg(now runnable via /dbg+HOME fix)
    # + angr + ropper on image 0.3; identical RAISED budget 30 exp / 3600 s.
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p39_pwn" / "c1"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.3"
    PWNDBG_EXPOSED = True
    ANGR_EXPOSED = True
    PWN_BUDGET = {"max_experiments": 30, "wall_s": 3600, "exp_timeout_s": 60}
elif _RUN_ID.startswith("p16bc0"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p16b_c0"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.1"
    PWNDBG_EXPOSED = False
    PWN_BUDGET = {"max_experiments": 30, "wall_s": 3600, "exp_timeout_s": 60}
else:
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p14_c0"
    pwn_service_harness.PWN_IMAGE = "ctfagent-pwn:0.2"
    PWNDBG_EXPOSED = True
    PWN_BUDGET = {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60}
# Surface the specialist symbolic/gadget tools only on the C1+tools route.
PWN_TOOLS = TOOLS + (["angr (symbolic; import angr -> angr.claripy)", "ropper"] if ANGR_EXPOSED else [])
c0_cli.C0_BUDGET = PWN_BUDGET
c0_cli.CryptoHarness = PwnServiceHarness
c0_cli.__doc__ = __doc__
CliError = c0_cli.CliError


def cmd_info(run_id, sess, args):
    d = Path(sess["challenge_dir"])
    ch = json.loads((d / "challenge.json").read_text())
    # Opening the harness resolves the deploy (unpacks archives, picks the real ELF, collects shipped
    # libs) so info reports the paths the agent should actually analyze.
    h = c0_cli.open_harness(run_id, sess)
    mani = getattr(h, "manifest", None)
    if mani:
        files = [{"name": "target", "container_path": "/input/target",
                  "note": f"the real ELF ({mani['target_rel']}); analyze this"}]
        files += [{"name": rel, "container_path": f"/input/tree/{rel}"}
                  for rel in mani.get("public_files", []) if rel != mani["target_rel"]]
        deploy_note = "; ".join(mani.get("notes", []))
    else:
        files = [{"name": f, "size": (d / f).stat().st_size, "container_path": f"/input/{f}"}
                 for f in ch.get("files", [])]
        deploy_note = None
    pwndbg_hint = (" (pwndbg: gdb -q -nx -ex 'source /opt/pwndbg/gdbinit.py')" if PWNDBG_EXPOSED else "")
    angr_hint = (" angr is available for input->state / VM / logic-check reasoning "
                 "(import angr; claripy = angr.claripy); it can state-explode, so guard it "
                 "(bounded input, find/avoid markers, step/time cap) and it is the wrong tool "
                 "for heap/pure-ROP." if ANGR_EXPOSED else "")
    print(json.dumps({
        "category": ch["category"], "title": ch["title"], "description": ch["description"],
        "flag_format": ch.get("flag_format"), "files": files, "budget": PWN_BUDGET,
        "remaining": c0_cli._remaining(sess), "tools": PWN_TOOLS,
        "pwndbg": "available" if PWNDBG_EXPOSED else "NOT installed",
        "angr": "available" if ANGR_EXPOSED else "NOT installed",
        "deploy": deploy_note,
        "target": f"a live service on 127.0.0.1:{pwn_service.DEFAULT_PORT} (env PORT); the flag is only "
                  "reachable by exploiting it",
        "how": "each `exp` is python3 run as the agent uid in a --network none container. Analyze the "
               "real binary at /input/target (read-only; other public files under /input/tree/) with "
               "the tools via subprocess" + pwndbg_hint + "." + angr_hint +
               " NOTE: /work is noexec and /input is read-only, so to run the binary under "
               "gdb/pwndbg use the exec-able debug copy the boundary places at /dbg/target "
               "(same bytes as the live target; shipped libs, if any, at /dbg/libs). HOME is "
               "preset to a writable dir so pwndbg loads cleanly. To "
               "hit the live target, use the session layer over a loopback tube, e.g.:\n"
               "    import os, session\n"
               "    s = session.Session(remote=('127.0.0.1', int(os.environ['PORT'])), log_dir='/work/s')\n"
               "    s.recvuntil(b'...'); s.send(payload); print(s.recvall(timeout=3))\n"
               "The session auto-opens on first use. flag.txt sits in the service's cwd (also /flag.txt), "
               "readable only by the service uid, so you must drive the bug (e.g. shell then "
               "`cat flag.txt`) to see it. Writable scratch is /work. Inspect first: e01 cannot be cited "
               "as evidence."},
        indent=2))


def cmd_report(run_id, sess, args):
    prefix = sess["challenge_id"] + "-"
    refs = [r if r.startswith(prefix) else prefix + r for r in args[1:]]
    if refs and all(r[len(prefix):].startswith("e01_") for r in refs):
        raise CliError("inspect-first: e01 cannot be the evidence; cite a later experiment that "
                       "printed the flag from the live service")
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
