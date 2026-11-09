"""Solver-facing CLI for Web (C0), on the 2-uid web-service boundary (Phase 36).

  cd ~/ctf_agent_v3 && python3 arena/web_cli.py <run_id> info
  cd ~/ctf_agent_v3 && python3 arena/web_cli.py <run_id> exp <name>   < code.py
  cd ~/ctf_agent_v3 && python3 arena/web_cli.py <run_id> report <FLAG> <exp_id> [...]
  cd ~/ctf_agent_v3 && python3 arena/web_cli.py <run_id> give_up <analysis|impl|tool> <reason...>
  cd ~/ctf_agent_v3 && python3 arena/web_cli.py <run_id> status

Each `exp` runs your python as the AGENT uid inside one --network none container. The target web app
runs as a DIFFERENT uid behind a loopback HTTP server you reach ONLY at http://127.0.0.1:$PORT. The
server source and the flag file are service-owned (you cannot read them directly); the flag is reachable
only by exploiting the app over HTTP. Black-box: no source is given. Inspect first: e01 can't be evidence.
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
from solver import web_harness                      # noqa: E402
from solver.web_harness import WebServiceHarness, WEB_TOOLS, WEB_FINALS_TOOLS  # noqa: E402
from tools import web_service                        # noqa: E402

_RUN_ID = next((a for a in sys.argv[1:] if not a.startswith("-")), "")
if _RUN_ID.startswith("p43w"):
    # Phase 43 web finals: the C1 image (0.3, +ffuf/playwright) + the skills/web router pack.
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p43_web" / "web"
    web_harness.WEB_IMAGE = "ctfagent-web:0.3"
    WEB_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
elif _RUN_ID.startswith("p36w"):
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p36_web" / "web"        # Phase 36 real web holdout (wr_*)
    web_harness.WEB_IMAGE = "ctfagent-web:0.2"
    WEB_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}
else:
    c0_cli.C0_ROOT = PROJECT_ROOT / "store" / "p36_web" / "web"
    web_harness.WEB_IMAGE = "ctfagent-web:0.2"
    WEB_BUDGET = {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90}

# Surface the attack tools present in the selected image (finals extras only on 0.3).
TOOLS = list(WEB_TOOLS)
if web_harness.WEB_IMAGE == web_harness.WEB_IMAGE_FINALS:
    TOOLS += list(WEB_FINALS_TOOLS)
c0_cli.C0_BUDGET = WEB_BUDGET
c0_cli.CryptoHarness = WebServiceHarness             # open_harness builds the web-service harness
c0_cli.__doc__ = __doc__
CliError = c0_cli.CliError


def cmd_info(run_id, sess, args):
    # Show only the PUBLIC challenge card (arena handout), never the staged private source.
    pub = PROJECT_ROOT / "arena" / "real_web" / sess["challenge_id"] / "challenge.json"
    ch = json.loads(pub.read_text())
    print(json.dumps({
        "category": ch["category"], "title": ch.get("title"), "description": ch["description"],
        "flag_format": ch.get("flag_format"), "files": ch.get("files", []), "budget": WEB_BUDGET,
        "remaining": c0_cli._remaining(sess), "tools": TOOLS,
        "target": f"a live web app on http://127.0.0.1:{web_service.DEFAULT_PORT} (env PORT); the flag is "
                  "reachable only by exploiting it over HTTP (black-box: no source, no direct file read)",
        "how": "each `exp` is python3 run as the agent uid in a --network none container. Talk to the app "
               "ONLY over loopback HTTP, e.g.:\n"
               "    import os, requests\n"
               "    base = 'http://127.0.0.1:' + os.environ['PORT']\n"
               "    r = requests.get(base + '/'); print(r.status_code, r.text[:2000])\n"
               "or use the cookie-persistent client: `import web_client; c = web_client.WebClient(base)`. "
               "Enumerate routes/params, find the bug (auth/cookie, LFI/path traversal, injection, IDOR, "
               "etc.), and make the app disclose the flag. Writable scratch is /work. Inspect first: e01 "
               "cannot be cited as evidence; the cited experiment must PRINT the flag it got from the app.",
        **({"tool_hint": "This image also carries sqlmap/ffuf (subprocess them against 127.0.0.1:$PORT) "
                         "and a best-effort headless chromium via playwright (verify "
                         "/opt/ctfagent/playwright_status.txt before relying on it). Identify the bug "
                         "class FIRST; a wrong-class tool is budget you will not get back."}
            if web_harness.WEB_IMAGE == web_harness.WEB_IMAGE_FINALS else {})},
        indent=2))


def cmd_report(run_id, sess, args):
    prefix = sess["challenge_id"] + "-"
    refs = [r if r.startswith(prefix) else prefix + r for r in args[1:]]
    if refs and all(r[len(prefix):].startswith("e01_") for r in refs):
        raise CliError("inspect-first: e01 cannot be the evidence; cite a later experiment that "
                       "printed the flag from the live app")
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
