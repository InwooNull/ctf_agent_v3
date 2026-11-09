"""Phase 46a: harness-integrity fixes for the two Phase-45 HUMAN-GATE items.

(1) parallel scratchpad clobber -> per-run isolated scratch dir (unique by run_id), so
    two concurrent blind solvers cannot overwrite each other's experiment code.
(2) /work EFBIG + OOM on large forensics inputs -> the misc harness sizes the container's
    fsize/memory limits to the input, so a 128 MB+ file writes to /work without EFBIG.
    Isolation (--network none, read-only root, cap-drop, no-new-privileges) is preserved.

Offline / cost-0: no live solver agent. The 128 MB end-to-end write is a docker harness
test, gated on the misc image (no Claude tokens).
"""
import sys
import tempfile
import threading
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
import json  # noqa: E402
from solver.misc_harness import MiscHarness, agent_scratch_dir, MISC_IMAGE_FINALS, MISC_IMAGE  # noqa: E402
from tools import sandbox  # noqa: E402


class TestScratchIsolation(unittest.TestCase):
    def test_distinct_run_ids_get_distinct_dirs(self):
        with tempfile.TemporaryDirectory() as t:
            a = agent_scratch_dir(t, "p45ms-mr_AAAAAA")
            b = agent_scratch_dir(t, "p45ms-mr_BBBBBB")
            self.assertNotEqual(a, b)
            self.assertTrue(a.is_dir() and b.is_dir())

    def test_two_concurrent_agents_no_clobber(self):
        """Simulate two blind solvers writing+reading their experiment code concurrently,
        each via its own run_id scratch dir, many iterations -> every read sees its OWN
        content (0 clobber). A shared fixed path would race; the per-run dir does not."""
        with tempfile.TemporaryDirectory() as t:
            errors = []

            def agent(run_id, tag):
                try:
                    d = agent_scratch_dir(t, run_id)
                    for i in range(300):
                        payload = f"{tag}-{i}\n" * 50
                        (d / "code.py").write_text(payload)
                        back = (d / "code.py").read_text()
                        if back != payload:
                            errors.append((run_id, i))
                except Exception as e:                      # pragma: no cover
                    errors.append((run_id, repr(e)))

            t1 = threading.Thread(target=agent, args=("p45ms-mr_AAAAAA", "A"))
            t2 = threading.Thread(target=agent, args=("p45ms-mr_BBBBBB", "B"))
            t1.start(); t2.start(); t1.join(); t2.join()
            self.assertEqual(errors, [], f"scratch clobber detected: {errors[:3]}")


def _make_big_challenge(tmp, cid, size_bytes):
    d = Path(tmp) / cid
    d.mkdir(parents=True)
    (d / "challenge.json").write_text(json.dumps(
        {"id": cid, "category": "misc", "files": ["big.bin"], "description": "x",
         "flag_format": "flag{...}"}))
    with open(d / "big.bin", "wb") as f:                    # sparse: cheap on disk
        f.truncate(size_bytes)
    return d


class TestEfbigLimitsSizing(unittest.TestCase):
    """Unit (no docker): a 128 MB input raises fsize + memory while isolation flags stay."""

    def test_large_input_raises_fsize_and_memory_keeps_isolation(self):
        with tempfile.TemporaryDirectory() as t:
            chal = _make_big_challenge(t, "mr_big", 128 * 1024 * 1024)
            h = MiscHarness("r1", chal, store_root=Path(t) / "store")
            # fsize raised well past the 128 MB input (and above the old 16 MB default)
            self.assertGreaterEqual(h.input_fsize_bytes, 128 * 1024 * 1024)
            self.assertGreater(h.input_fsize_bytes, 16 * 1024 * 1024)
            c = h.sandbox_config["container"]
            self.assertEqual(c["limits"]["memory"], "1g")     # headroom bumped for a large input
            # isolation UNCHANGED
            self.assertEqual(c["network"], "none")
            self.assertTrue(c["read_only_root"])
            self.assertEqual(c["cap_drop"], ["ALL"])
            self.assertTrue(c["no_new_privileges"])

    def test_small_input_keeps_default_limits(self):
        with tempfile.TemporaryDirectory() as t:
            chal = _make_big_challenge(t, "mr_small", 1024)
            h = MiscHarness("r2", chal, store_root=Path(t) / "store")
            self.assertEqual(h.sandbox_config["container"]["limits"]["memory"], "256m")


_IMG = MISC_IMAGE_FINALS if sandbox.image_available(MISC_IMAGE_FINALS) else MISC_IMAGE
_DOCKER = sandbox.docker_available() and sandbox.image_available(_IMG)

BIG_WRITE = r'''
# write a 128 MiB file into /work in chunks, then stat it -> proves no EFBIG.
import os
path = "/work/big.out"
chunk = b"\0" * (1024 * 1024)
with open(path, "wb") as f:
    for _ in range(160):          # 160 MiB > old 16 MiB fsize limit
        f.write(chunk)
print("WROTE_BYTES", os.path.getsize(path))
'''


@unittest.skipUnless(_DOCKER, f"{_IMG} not built locally")
class TestEfbigEndToEnd(unittest.TestCase):
    def test_128mb_write_to_work_no_efbig(self):
        with tempfile.TemporaryDirectory() as t:
            chal = _make_big_challenge(t, "mr_bige2e", 128 * 1024 * 1024)
            h = MiscHarness("e2e", chal, store_root=Path(t) / "store", image=_IMG)
            o = h.run_experiment({"name": "bigwrite", "code": BIG_WRITE, "timeout": 120})
            self.assertEqual(o.execution_status, "ok", o.stdout)
            self.assertIn("WROTE_BYTES 167772160", o.stdout)   # 160 MiB written, no EFBIG


if __name__ == "__main__":
    unittest.main()
