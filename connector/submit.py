"""Submit a flag to the live CTFd and record the outcome — the human-operator CLI.

  python3 -m connector.submit <cid|ctfd_id|title> <flag> [--force]

This is the project's one outward action from the command line. It is a thin wrapper
over `connector.submit_gate.SubmitGate` (role=orchestrator), so the CLI and the agent
pipeline share ONE governance chokepoint and ONE append-only log:

  - resolves cid (live_<n>) / raw int / exact title -> ctfd_id via store/live/manifest.json,
  - refuses to resubmit a flag already tried, or a challenge already solved,
  - enforces the per-challenge attempt cap and rate-limit backoff,
  - appends store/live/submissions.jsonl (flag_sha256 only — never the flag).

Sub-agents never import this module to submit; they report candidates and the
orchestrator decides. See connector/submit_gate.py for the rules.
"""
import argparse
import json
import sys
from pathlib import Path

from connector.ctfd_client import CTFdClient, CTFdError, RateLimited
from connector.submit_gate import (
    SubmitGate, SubmitGateError, DuplicateSubmission,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STORE = PROJECT_ROOT / "store" / "live"
MANIFEST = STORE / "manifest.json"
SUBLOG = STORE / "submissions.jsonl"


def _load_manifest():
    if MANIFEST.is_file():
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {}


def resolve_ctfd_id(target, manifest=None):
    """Accept 'live_42', '42', or an exact title; return the integer CTFd id."""
    manifest = manifest if manifest is not None else _load_manifest()
    s = str(target)
    if s.startswith("live_"):
        return int(s[len("live_"):])
    if s.isdigit():
        return int(s)
    for cid, rec in manifest.items():
        if rec.get("title") == s:
            return int(rec["ctfd_id"])
    raise CTFdError(f"cannot resolve challenge target {target!r}")


def submit(client, target, flag, force=False, log=SUBLOG):
    """Returns (status, message). status 'already_correct' if we solved it before.

    `force` re-submits even if the flag was tried before (operator override).
    """
    ctfd_id = resolve_ctfd_id(target)
    gate = SubmitGate.for_orchestrator(client, log_path=log)
    try:
        return gate.submit_flag_value(ctfd_id, flag, force=force)
    except DuplicateSubmission as e:
        return "already_correct", str(e)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Submit a flag to the live CTFd")
    ap.add_argument("target", help="cid (live_<n>), raw ctfd id, or exact title")
    ap.add_argument("flag", help="the flag string to submit")
    ap.add_argument("--force", action="store_true", help="submit even if already tried")
    ap.add_argument("--env", default=None)
    args = ap.parse_args(argv)
    try:
        client = CTFdClient.from_env(args.env) if args.env else CTFdClient.from_env()
        status, message = submit(client, args.target, args.flag, force=args.force)
    except RateLimited as e:
        print(f"[submit] RATE LIMITED: {e}", file=sys.stderr)
        return 3
    except (CTFdError, SubmitGateError) as e:
        print(f"[submit] ERROR: {e}", file=sys.stderr)
        return 2
    print(f"[submit] {args.target}: {status}  {message}")
    return 0 if status in ("correct", "already_correct", "already_solved") else 1


if __name__ == "__main__":
    raise SystemExit(main())
