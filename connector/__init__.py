"""Phase 24: live CTFd connector (fetch challenges, submit flags).

Stdlib-only I/O layer between a live CTFd instance (the ACDC 2026 qualifier) and
the offline solver pipelines. It never solves anything itself; it only moves data:
  - fetch:  CTFd  -> arena/live/<cid>/{challenge.json, files...}  (same blind layout
            as eval/real_loader.py, so the existing harnesses plug in unchanged)
  - submit: a flag -> POST /api/v1/challenges/attempt -> correct|incorrect|...

Secrets (URL/token/creds) live in config/acdc.env (git-ignored, chmod 600) and are
read via load_env(); nothing in this package hardcodes them.
"""
