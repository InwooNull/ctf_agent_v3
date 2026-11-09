"""Misc/Forensics solving harness — same reasoner-facing API and log convention
as the crypto/rev harnesses (run_experiment / record_hypothesis /
report_candidate / get_state / check_budget; events/commands/experiments/
candidates.jsonl, state.json), but experiments run in the ctfagent-misc image.

The experiment is python source run as `python3 -I /work/<name>.py` INSIDE the
container (untrusted, --network none, read-only root, non-root, cap-drop ALL);
it may drive file/binwalk/exiftool/steghide/foremost/outguess/tshark/pdftotext/
convert/zsteg and pyzbar/pillow/numpy via subprocess/import. The challenge
files are mounted read-only at /input. The root FS is read-only, so tools that
need scratch space must use /work (e.g. TMPDIR=/work, carve into /work).

Most Misc/Forensics work is on LOCAL files, so no 2-uid service boundary is
needed: a plain container with --network none suffices. Evidence/scoring reuse
the shared verifier rule (a container experiment whose stdout printed the flag).
"""
from solver.crypto_harness import CryptoHarness, ExperimentOutcome  # noqa: F401

MISC_IMAGE = "ctfagent-misc:0.1"  # pinned baseline (test_misc_pipeline); the finals
# image ctfagent-misc:0.3 (Phase 42: +sleuthkit/john/zbar/vol3+symbols/hashcat) is
# selected explicitly via image= by a C1 misc run, exactly as rev kept 0.1 default and
# passed 0.2 to its C1 runner. 0.3 tool knowledge lives in the skills/misc router pack.
MISC_IMAGE_FINALS = "ctfagent-misc:0.5"  # Phase 49a: 0.4 + tesseract(OCR)/opencv(cv2)/stegseek+wordlist
MISC_IMAGE_CRYPTO = "ctfagent-misc:0.6"  # Phase 52: 0.5 + pycryptodome (AES/RSA final-layer decryption in-container)
# Tools available inside the image (for prompt/info surfaces; execution is via
# the single `pycode` entry which may subprocess any of these).
MISC_TOOLS = (
    "file", "binwalk", "exiftool", "steghide", "foremost", "outguess",
    "tshark", "tcpdump", "pdftotext", "convert", "xxd", "strings", "zsteg",
)
# Extra specialist tools present ONLY in MISC_IMAGE_FINALS; surfaced to a C1 run.
# (0.4 adds the gcc/g++ toolchain so a solver can compile+run source it recovers.)
MISC_FINALS_TOOLS = (
    "7z", "vol", "fls", "icat", "tsk_recover", "mmls", "fsstat",
    "john", "zip2john", "zbarimg", "hashcat", "gcc", "g++", "make",
    "tesseract", "stegseek", "python3 (import cv2)",   # 0.5: OCR, stego-crack, OpenCV
)
# a password wordlist is bundled in 0.5 at this path (for stegseek/john).
MISC_WORDLIST = "/opt/wordlists/rockyou.txt"
MISC_PYLIBS = ("PIL", "numpy", "pyzbar")


import copy as _copy
import os as _os
from pathlib import Path as _Path

# Phase 46a bounds for large forensics inputs (memory dumps / disk images). /work is a
# disk-backed bind mount, so a big fsize just needs its rlimit raised; memory gets headroom.
_FSIZE_FLOOR_LARGE = 512 * 1024 * 1024      # 512 MiB per-file write ceiling for large inputs
_FSIZE_CAP = 4 * 1024 * 1024 * 1024         # never raise fsize past 4 GiB
_LARGE_INPUT_BYTES = 32 * 1024 * 1024       # "large" threshold: bump memory headroom above this
_MEM_LARGE = "1g"
_PIDS_CRACK_CLASS = 512                      # Phase 52: per-run pid ceiling for multithreaded crack tools


def agent_scratch_dir(store_root, run_id):
    """A UNIQUE per-run host scratch directory (Phase 46a). Parallel blind solvers must
    write their experiment code here (keyed by run_id) instead of a shared repo-root path,
    so two concurrent runs cannot clobber each other's scratch file."""
    d = _Path(store_root) / run_id / "scratch"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _largest_input_bytes(challenge_dir):
    cd = _Path(challenge_dir)
    sizes = [p.stat().st_size for p in cd.rglob("*") if p.is_file()]
    return max(sizes) if sizes else 0


class MiscHarness(CryptoHarness):
    def __init__(self, run_id, challenge_dir, store_root=None, budget=None,
                 image=MISC_IMAGE, clock=None):
        super().__init__(run_id, challenge_dir, store_root=store_root,
                         budget=budget, image=image, clock=clock)
        # Size the container's per-file write limit (and memory headroom) to the input, so
        # a 128 MB+ image can be extracted into /work without EFBIG / a tiny OOM ceiling.
        # Isolation is UNCHANGED: --network none, --read-only root, cap-drop ALL,
        # no-new-privileges and the /work bind mount all stay exactly as configured; only
        # the fsize/memory NUMBERS grow. We deep-copy so no other harness instance is affected.
        self.sandbox_config = _copy.deepcopy(self.sandbox_config)
        lim = self.sandbox_config["container"]["limits"]
        largest = _largest_input_bytes(challenge_dir)
        want = max(int(lim.get("fsize_bytes", 0)), largest * 16)
        if largest > 0:
            want = max(want, _FSIZE_FLOOR_LARGE)
        lim["fsize_bytes"] = min(want, _FSIZE_CAP)
        if largest > _LARGE_INPUT_BYTES:
            lim["memory"] = _MEM_LARGE
        # Phase 52 (user-approved HUMAN-GATE fix): crack-class tools (stegseek/john, multi-
        # threaded) hit the 128-pid ceiling (BlockingIOError) when parallelising a wordlist
        # sweep. Raise the per-RUN pids ceiling for misc only. This is a RUNTIME override on a
        # deep-copied config -- config/sandbox.json is NOT edited (governance hash preserved),
        # and NO isolation boundary changes: --network none, --read-only root, cap-drop ALL,
        # no-new-privileges, non-root, and /work-only rw all stay exactly as configured.
        lim["pids_limit"] = max(int(lim.get("pids_limit", 128)), _PIDS_CRACK_CLASS)
        self.input_fsize_bytes = lim["fsize_bytes"]        # exposed for tests/inspection
        self.pids_limit = lim["pids_limit"]
        # Phase 52 (user-approved): persist ONE /work across all experiments of a run so a
        # multi-layer extraction chain (mandiant: PDF->PNG->7z->JPEG->AES blob) is not rebuilt
        # from scratch every experiment (the proximate cause of mr_42745d's budget exhaustion).
        # OPT-IN per route (env MISC_PERSIST_WORK=1), default OFF — exactly the crypto/rev
        # discipline, so every existing lane/test keeps the per-experiment jail unchanged.
        # Blindness is unaffected: /work is the agent's own scratch, never holds the flag/vault
        # (those stay unmounted + chmod-0).
        if _os.environ.get("MISC_PERSIST_WORK") == "1":
            self.persist_work = True
