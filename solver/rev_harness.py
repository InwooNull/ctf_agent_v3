"""Reverse solving harness — same reasoner-facing API and log convention as the
crypto harness (run_experiment / record_hypothesis / report_candidate /
get_state / check_budget; events/commands/experiments/candidates.jsonl,
state.json), but experiments run in the ctfagent-rev image.

The experiment is python source run as `python3 -I /work/<name>.py` INSIDE the
container (untrusted, --network none, read-only root, non-root, cap-drop ALL);
it may drive objdump/readelf/nm/gdb/file/xxd/gcc via subprocess. The challenge
binary is mounted read-only at /input. The root FS is read-only, so tools that
need scratch space must use /work (e.g. TMPDIR=/work).
"""
from solver.crypto_harness import CryptoHarness, ExperimentOutcome  # noqa: F401

REV_IMAGE = "ctfagent-rev:0.3"
REV_TOOLS = ("objdump", "readelf", "nm", "gdb", "file", "xxd", "gcc", "strings",
             "angr", "analyzeHeadless", "rea")


# The rev container's memory ceiling. The pinned sandbox.json default is 256m,
# which OOM-kills the Ghidra 12.2 JVM used by the decompiler lane (measured:
# 256m -> SIGKILL/137; 2g -> clean decompile in ~85s on a tiny ELF, 1 CPU). angr
# also benefits from the extra headroom. We raise ONLY this value, in the
# non-pinned harness; config/sandbox.json and the 7 governance files stay
# byte-identical, and every security-isolation flag (--network none, read-only
# root, non-root --user, --cap-drop ALL, no-new-privileges) is untouched.
REV_MEMORY = "2g"


class RevHarness(CryptoHarness):
    def __init__(self, run_id, challenge_dir, store_root=None, budget=None, image=REV_IMAGE, clock=None):
        super().__init__(run_id, challenge_dir, store_root=store_root, budget=budget, image=image, clock=clock)
        # Override only the memory limit; sandbox.py mirrors it to --memory-swap.
        lim = dict(self.sandbox_config["container"].get("limits", {}))
        lim["memory"] = REV_MEMORY
        self.sandbox_config["container"] = dict(self.sandbox_config["container"], limits=lim)
