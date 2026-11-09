"""Pwn solving harness — same reasoner-facing API and log convention as the
crypto/rev harnesses, but experiments run in the ctfagent-pwn image and may use
the interactive session layer (solver/session.py) to drive a running process.

Each experiment is still ONE container invocation (untrusted, --network none,
read-only root, non-root, cap-drop ALL); the stateful send/leak/re-send loop
happens INSIDE it against a LOCAL process started by pwntools. There is no
persistent cross-call container and no network — the single-shot tool contract
(tools/run_tool) is unchanged; the session is a library used within one run.

To let the experiment `import session` while keeping the Phase 4.5 isolation
(`python3 -I`, so /work is not on sys.path and planted os.py/inspect.py cannot
shadow stdlib), the harness:
  * copies solver/session.py into the jail at /work/_lib/session.py, and
  * prepends a two-line bootstrap to the experiment that inserts ONLY /work/_lib
    onto sys.path at run time (that dir holds session.py and nothing else, so no
    stdlib name can be shadowed).
"""
import json
from pathlib import Path

from solver.crypto_harness import CryptoHarness, ExperimentOutcome  # noqa: F401

PWN_IMAGE = "ctfagent-pwn:0.1"
PWN_TOOLS = ("gcc", "gdb", "objdump", "readelf", "nm", "file", "python3",
             "pwntools", "ROPgadget", "one_gadget")
SESSION_SRC = Path(__file__).resolve().parent / "session.py"
SESSION_LIB_DIR = "_lib"
# Inserted at the top of every pwn experiment. Explicit, minimal, run-time only.
_BOOTSTRAP = (
    "import sys as _sys\n"
    "_sys.path.insert(0, '/work/%s')  # harness: session layer only\n"
    "del _sys\n"
) % SESSION_LIB_DIR


class PwnHarness(CryptoHarness):
    def __init__(self, run_id, challenge_dir, store_root=None, budget=None,
                 image=PWN_IMAGE, clock=None):
        super().__init__(run_id, challenge_dir, store_root=store_root, budget=budget,
                         image=image, clock=clock)
        self.elog.append_event("pwn_harness_ready", session_layer=str(SESSION_SRC.name))

    def run_experiment(self, spec):
        """spec: {name, code, timeout?, nondeterministic?, setup_files?}. `code` may `import session`.

        setup_files: {relpath: bytes|str} written into the jail (/work) BEFORE the
        experiment runs. Used to place a runtime 'server-side' file the target reads
        (e.g. flag.txt) that is NOT one of the agent-visible challenge files — the
        exploit must reach it through the bug, it is not handed the contents.

        Pwn experiments default to nondeterministic=True (an exploit that leaks a
        randomized address is not reproducible by input hash), so results are not
        dedup-cached unless the caller explicitly marks the step deterministic.
        """
        name = spec["name"]
        # place session.py in the same jail the parent will mount at /work
        exp_work = self.work_dir / name
        lib = exp_work / SESSION_LIB_DIR
        lib.mkdir(parents=True, exist_ok=True)
        (lib / "session.py").write_text(SESSION_SRC.read_text())
        for rel, content in (spec.get("setup_files") or {}).items():
            dest = exp_work / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content.encode() if isinstance(content, str) else content)

        wrapped = dict(spec)
        wrapped["code"] = _BOOTSTRAP + spec["code"]
        wrapped.setdefault("nondeterministic", True)
        return super().run_experiment(wrapped)
