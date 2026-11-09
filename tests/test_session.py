"""Session layer (solver/session.py): pure byte-safe/budget logic on the host
(no pwntools), the tube-driving logic via a fake tube, and one real in-container
stateful round trip (skipped if the pwn image is absent)."""
import json
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(PROJECT_ROOT))
from solver import session as S  # noqa: E402
from tools import sandbox  # noqa: E402

PWN_IMAGE = "ctfagent-pwn:0.1"


class PureHelpers(unittest.TestCase):
    def test_safe_repr_bounds_and_byte_safe(self):
        r = S.safe_repr(b"\xff\x00ABC", limit=3)
        self.assertEqual(r["len"], 5)
        self.assertTrue(r["truncated"])
        self.assertEqual(bytes.fromhex(r["hex"]), b"\xff\x00A")
        with self.assertRaises(TypeError):
            S.safe_repr("not-bytes")

    def test_output_budget(self):
        b = S.OutputBudget(cap=10)
        self.assertTrue(b.add(6))
        self.assertFalse(b.would_exceed(4) is True and b.used > 10)  # 6+4==10 ok
        self.assertFalse(b.would_exceed(4))
        self.assertTrue(b.would_exceed(5))
        self.assertTrue(b.add(4))
        self.assertEqual(b.remaining, 0)
        self.assertFalse(b.add(1))        # 11 > 10

    def test_interaction_record_shape(self):
        rec = S.interaction_record(3, "recv", "recv", b"abc", S.OutputBudget(100), spill_ref="x.bin")
        self.assertEqual((rec["seq"], rec["op"], rec["direction"], rec["bytes"]), (3, "recv", "recv", 3))
        self.assertEqual(rec["spill_ref"], "x.bin")


class FakeTube:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False
        self.polled = False
        self.pid = 1234

    def send(self, data):
        self.sent.append(bytes(data))

    def recv(self, numb=4096, timeout=None):
        return self.chunks.pop(0) if self.chunks else b""

    recvuntil = recvline = recvall = lambda self, *a, **k: (self.chunks.pop(0) if self.chunks else b"")

    def close(self):
        self.closed = True

    def poll(self, block=False):
        self.polled = True
        return 0


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _session(tube, **kw):
    d = tempfile.mkdtemp()
    s = S.Session(["/bin/true"], log_dir=d, **kw)
    s._tube = tube
    s._t0 = s.clock()
    return s


class TubeLogic(unittest.TestCase):
    def test_send_recv_accounting_and_transcript(self):
        t = FakeTube([b"hello"])
        s = _session(t)
        s.send(b"ping")
        got = s.recv()
        self.assertEqual(got, b"hello")
        self.assertEqual(t.sent, [b"ping"])
        self.assertEqual(s.budget.used, 5)        # recv counts, send does not
        s.close()
        recs = [json.loads(l) for l in s.transcript_path.read_text().splitlines()]
        dirs = [r["direction"] for r in recs]
        self.assertIn("send", dirs)
        self.assertIn("recv", dirs)

    def test_output_cap_raises_and_logs(self):
        t = FakeTube([b"X" * 50])
        s = _session(t, output_cap=10)
        with self.assertRaises(S.SessionOutputCap):
            s.recv()
        s.close()
        self.assertTrue(any(r.get("note") == "output_cap"
                            for r in map(json.loads, s.transcript_path.read_text().splitlines())))

    def test_spill_artifact_for_large_chunk(self):
        big = b"A" * (S.INLINE_PREVIEW + 100)
        t = FakeTube([big])
        s = _session(t, output_cap=10 ** 7)
        s.recv()
        spills = list(Path(s.log_dir).glob("spill_*.bin"))
        self.assertEqual(len(spills), 1)
        self.assertEqual(spills[0].read_bytes(), big)   # full bytes spilled, not inline
        s.close()

    def test_wall_timeout(self):
        clk = FakeClock()
        t = FakeTube([b"x"])
        s = _session(t, wall_s=5, clock=clk)
        clk.t = 6.0
        with self.assertRaises(S.SessionWallTimeout):
            s.recv()
        s.close()

    def test_close_reaps_and_is_idempotent(self):
        t = FakeTube([])
        s = _session(t)
        s.close()
        self.assertTrue(t.closed and t.polled)
        s.close()                      # no error on second close
        self.assertTrue(s.closed)

    def test_exit_cleans_up_on_exception(self):
        # __exit__ must reap the tube even when the with-body raised (open() itself
        # needs pwntools, so drive __exit__ directly with a fake tube attached).
        t = FakeTube([])
        s = _session(t)
        self.assertFalse(s.__exit__(ValueError, ValueError("boom"), None))  # does not suppress
        self.assertTrue(t.closed)

    def test_send_requires_bytes(self):
        s = _session(FakeTube([]))
        with self.assertRaises(TypeError):
            s.send("str-not-bytes")
        s.close()


@unittest.skipUnless(sandbox.image_available(PWN_IMAGE), f"{PWN_IMAGE} not present")
class InContainerSession(unittest.TestCase):
    """A real stateful round trip: a tiny program keeps a running sum across
    multiple send/recv rounds, driven through the session layer inside the
    container (untrusted, --network none)."""

    def test_stateful_rounds_in_container(self):
        prog = textwrap.dedent("""
            #include <stdio.h>
            int main(void){ setvbuf(stdout,0,_IONBF,0); int x,s=0;
                while (scanf("%d",&x)==1){ s+=x; printf("sum=%d\\n", s); } return 0; }
        """)
        driver = textwrap.dedent("""
            import sys; sys.path.insert(0, '/work/_lib')
            import subprocess, session
            subprocess.run(['gcc','-w','-o','/work/acc','/work/acc.c'], check=True)
            with session.Session(['/work/acc'], log_dir='/work/sess', wall_s=15) as s:
                s.sendline(b'10'); a = s.recvuntil(b'\\n')
                s.sendline(b'5');  b = s.recvuntil(b'\\n')     # state kept: 10 then 15
                print('A', a.strip().decode()); print('B', b.strip().decode())
        """)
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "_lib").mkdir()
            (d / "_lib" / "session.py").write_text((PROJECT_ROOT / "solver" / "session.py").read_text())
            (d / "acc.c").write_text(prog)
            (d / "driver.py").write_text(driver)
            argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{d}:/work:rw",
                    "-w", "/work", "--user", f"{__import__('os').getuid()}:{__import__('os').getgid()}",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--memory", "512m", "--pids-limit", "256",
                    "-e", "TERM=xterm", "-e", "HOME=/work", "-e", "TMPDIR=/work",
                    PWN_IMAGE, "python3", "-I", "/work/driver.py"]
            p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
            self.assertIn("A sum=10", p.stdout, msg=p.stderr[-800:])
            self.assertIn("B sum=15", p.stdout, msg=p.stderr[-800:])
            # the session transcript recorded both rounds, byte-safe
            tr = (d / "sess" / "session.jsonl").read_text().splitlines()
            ops = [json.loads(l)["op"] for l in tr]
            self.assertEqual(ops.count("open"), 1)
            self.assertGreaterEqual(ops.count("send"), 2)
            self.assertGreaterEqual(ops.count("recvuntil"), 2)


if __name__ == "__main__":
    unittest.main()
