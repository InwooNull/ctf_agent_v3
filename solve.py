#!/usr/bin/env python3
"""solve — the ONE sanctioned entrypoint for every CTF input.

    solve <input> [--bench] [--ctfd] [--run] [--env PATH]

(Also runnable as `python3 solve.py <input> ...`. Installed as `solve` on PATH via
a symlink to this script; it resolves its own location so it works from any
directory.)

<input> is auto-detected into one of four kinds:
    ctfd   a live CTFd instance (base URL, or a URL carrying a ?token=, or --ctfd):
           challenges are collected via connector.ctfd_client (no re-implementation).
    url    a single live challenge target (remote web / service URL).
    dir    a directory of already-downloaded challenge files.
    file   a single challenge file.

Mode (the CM switch): DEFAULT is "contest" (a real competition — network to the
challenge target allowed, no vault, goal = maximise solves in budget). "--bench"
is the ONLY way into the blind measurement mode (`--network none`, vault + scorer
key), whose behaviour is unchanged by this phase.

EVERY CTF input must come through here and route into the managed pipeline
(orchestrator.competition). Ad-hoc solving (raw scratch dirs like ctf_work/) is
forbidden — see CLAUDE.md.

CM1 scope: input auto-detection, mode resolution, and the routing PLAN are live and
tested. Actually executing a contest run against a live target is wired in CM2-CM5;
until then `--run` dispatches only the paths already proven and otherwise reports
exactly what is deferred. No over-claim.
"""
import argparse
import os
import sys
from urllib.parse import urlsplit

# Make `solve` runnable from ANY working directory, including via a PATH symlink
# (~/.local/bin/solve -> this file). Resolve the symlink to the real script location
# and ensure the project root (this file's directory) is importable, so the
# `orchestrator`/`connector`/... packages load regardless of the current directory.
_PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from orchestrator import mode as mode_mod

# input kinds
CTFD = "ctfd"
URL = "url"
DIR = "dir"
FILE = "file"

# A URL is treated as a CTFd instance (rather than a bare challenge target) when it
# carries a download token or points at a CTFd-shaped path. Otherwise http(s) -> url.
_CTFD_PATH_HINTS = ("/api/v2", "/api/v1", "/challenges", "/files/")


def _is_http(s):
    return isinstance(s, str) and s.lower().startswith(("http://", "https://"))


def detect_input(arg, ctfd=False):
    """Classify `arg` into CTFD / URL / DIR / FILE. `ctfd=True` forces CTFD for a URL.

    Pure and side-effect-free except for the local filesystem existence checks used
    to tell DIR from FILE. Raises ValueError when nothing matches."""
    if not arg or not str(arg).strip():
        raise ValueError("empty input")
    s = str(arg).strip()
    if _is_http(s):
        if ctfd:
            return CTFD
        parts = urlsplit(s)
        if "token=" in (parts.query or ""):
            return CTFD
        if any(h in (parts.path or "") for h in _CTFD_PATH_HINTS):
            return CTFD
        return URL
    if ctfd:
        raise ValueError(f"--ctfd given but {s!r} is not an http(s) URL")
    if os.path.isdir(s):
        return DIR
    if os.path.isfile(s):
        return FILE
    raise ValueError(f"cannot resolve input {s!r}: not a URL, directory, or file")


def resolve_mode(bench=False):
    """--bench -> bench mode; otherwise the default (contest)."""
    return mode_mod.BENCH if bench else mode_mod.DEFAULT


# how each input kind routes into the shared pipeline (labels; execution lands CM2-5)
_PIPELINE = {
    CTFD: "connector.ctfd_client -> orchestrator.competition",
    URL: "orchestrator.triage/route -> category harness (live target)",
    DIR: "local collect -> orchestrator.competition",
    FILE: "orchestrator.triage/route -> category harness (single)",
}


def build_plan(arg, bench=False, ctfd=False):
    """Resolve input + mode into a routing plan dict (no execution)."""
    kind = detect_input(arg, ctfd=ctfd)
    m = resolve_mode(bench=bench)
    prof = mode_mod.profile(m)
    return {
        "input": str(arg),
        "kind": kind,
        "mode": m,
        "network": prof["network"],
        "use_vault": prof["use_vault"],
        "auto_submit": prof["auto_submit"],
        "experience_tag": prof["experience_tag"],
        "pipeline": _PIPELINE[kind],
    }


def _format_plan(plan):
    return (
        "solve plan\n"
        f"  input         : {plan['input']}\n"
        f"  detected kind : {plan['kind']}\n"
        f"  mode          : {plan['mode']}"
        f"{'  (DEFAULT)' if plan['mode'] == mode_mod.DEFAULT else '  (explicit)'}\n"
        f"  network       : {plan['network']}\n"
        f"  vault         : {plan['use_vault']}\n"
        f"  auto-submit   : {plan['auto_submit']}  (candidate shown to user)\n"
        f"  experience tag: {plan['experience_tag']}\n"
        f"  pipeline      : {plan['pipeline']}"
    )


def main(argv=None, *, execute=None):
    ap = argparse.ArgumentParser(
        prog="solve", description="Single sanctioned entrypoint for CTF inputs.")
    ap.add_argument("input", help="CTFd URL / target URL / directory / file")
    ap.add_argument("--bench", action="store_true",
                    help="enter blind BENCH mode (--network none, vault). Default is contest.")
    ap.add_argument("--ctfd", action="store_true",
                    help="force treating the URL as a CTFd instance to collect from")
    ap.add_argument("--run", action="store_true",
                    help="execute the plan (CM2-CM5 wire live execution; dry by default)")
    ap.add_argument("--env", default=None, help="path to the CTFd env file")
    args = ap.parse_args(argv)

    try:
        plan = build_plan(args.input, bench=args.bench, ctfd=args.ctfd)
    except ValueError as e:
        print(f"[solve] ERROR: {e}", file=sys.stderr)
        return 2

    print(_format_plan(plan))
    if not args.run:
        print("[solve] dry plan (pass --run to execute).")
        return 0

    # CM5: --run executes the managed contest pipeline (collect -> rotation -> per
    # challenge skill_pack + scoped egress + solve -> evidence -> checkpoint -> writeup
    # -> candidate display). `execute` is injectable for tests; default is the real run.
    if execute is None:
        from orchestrator.contest_run import run_plan as execute
    return execute(plan, env=args.env)


if __name__ == "__main__":
    raise SystemExit(main())
