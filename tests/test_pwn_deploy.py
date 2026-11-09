"""Phase 15 harness-deployment fixes: host-side deploy resolver, session auto-open (footgun fix),
and the pwn-service own-port path. Docker-gated parts skip if the pwn image is absent; the rest are
pure-host and vault-free (synthetic fixtures built in a tempdir)."""
import json
import os
import struct
import sys
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver import pwn_deploy, session as S   # noqa: E402
from tools import pwn_service, sandbox         # noqa: E402

PWN_IMAGE = "ctfagent-pwn:0.2"


def _fake_elf(path, e_type=2, interp=True):
    """Write a minimal but structurally valid 64-bit ELF header with/without a PT_INTERP phdr."""
    e_phoff = 64
    e_phentsize = 56
    e_phnum = 1 if interp else 0
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2            # ELFCLASS64
    hdr[5] = 1            # little-endian
    hdr[16:18] = struct.pack("<H", e_type)
    hdr[32:40] = struct.pack("<Q", e_phoff)
    hdr[54:56] = struct.pack("<H", e_phentsize)
    hdr[56:58] = struct.pack("<H", e_phnum)
    phdrs = b""
    if interp:
        ph = bytearray(e_phentsize)
        ph[0:4] = struct.pack("<I", 3)      # PT_INTERP
        phdrs = bytes(ph)
    Path(path).write_bytes(bytes(hdr) + phdrs + b"\x00" * 32)


class DeployResolver(unittest.TestCase):
    def test_picks_elf_over_source_and_lib(self):
        with tempfile.TemporaryDirectory() as ch, tempfile.TemporaryDirectory() as outp:
            d = Path(ch)
            (d / "vuln.c").write_text("int main(){}")          # source must NOT be chosen
            _fake_elf(d / "libc.so.6", e_type=3, interp=False)  # a lib must NOT be chosen
            _fake_elf(d / "vuln", e_type=2, interp=True)        # the real executable
            (d / "challenge.json").write_text(json.dumps(
                {"files": ["vuln.c", "libc.so.6", "vuln"], "category": "pwn"}))
            m = pwn_deploy.resolve(d, Path(outp) / "dep")
            self.assertEqual(m["target_rel"], "vuln")
            self.assertTrue((Path(outp) / "dep" / "target").exists())

    def test_extracts_archive_and_finds_inner_elf_and_flag_decoy(self):
        with tempfile.TemporaryDirectory() as ch, tempfile.TemporaryDirectory() as outp:
            d = Path(ch)
            inner = d / "_stage"
            (inner / "chal").mkdir(parents=True)
            _fake_elf(inner / "chal" / "prog", e_type=2, interp=True)
            (inner / "chal" / "flag").write_text("FAKE_DECOY_FLAG")
            z = d / "share.zip"
            with zipfile.ZipFile(z, "w") as zf:
                zf.write(inner / "chal" / "prog", "chal/prog")
                zf.write(inner / "chal" / "flag", "chal/flag")
            (d / "challenge.json").write_text(json.dumps({"files": ["share.zip"], "category": "pwn"}))
            m = pwn_deploy.resolve(d, Path(outp) / "dep")
            self.assertEqual(m["target_rel"], "chal/prog")
            self.assertIn("chal/flag", m["flag_decoys"])

    def test_zip_slip_blocked(self):
        with tempfile.TemporaryDirectory() as ch, tempfile.TemporaryDirectory() as outp:
            d = Path(ch)
            z = d / "evil.zip"
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("../escape.txt", "pwned")
            (d / "challenge.json").write_text(json.dumps({"files": ["evil.zip"], "category": "pwn"}))
            with self.assertRaises(ValueError):
                pwn_deploy.resolve(d, Path(outp) / "dep")

    def test_shipped_ld_mode(self):
        with tempfile.TemporaryDirectory() as ch, tempfile.TemporaryDirectory() as outp:
            d = Path(ch)
            _fake_elf(d / "prog", e_type=2, interp=True)
            _fake_elf(d / "ld-linux-x86-64.so.2", e_type=3, interp=False)
            _fake_elf(d / "libc.so.6", e_type=3, interp=False)
            (d / "challenge.json").write_text(json.dumps(
                {"files": ["prog", "ld-linux-x86-64.so.2", "libc.so.6"], "category": "pwn"}))
            m = pwn_deploy.resolve(d, Path(outp) / "dep")
            self.assertEqual(m["lib_mode"], "shipped_ld")
            self.assertEqual(m["interp"], "ld-linux-x86-64.so.2")


class SessionAutoOpen(unittest.TestCase):
    """The Phase 14 footgun: a Session used without .open()/`with` raised 'session not open'. It must
    now auto-open on first send/recv. (Driven with a fake tube so the test needs no pwntools/docker.)"""

    def _session(self):
        s = S.Session(remote=("127.0.0.1", 9999), log_dir=tempfile.mkdtemp())
        opened = {"n": 0}

        class FakeTube:
            def __init__(self):
                self.sent = b""
            def send(self, data):
                self.sent += data
            def recv(self, numb=4096, timeout=None):
                return b"hello"

        def fake_open():
            if s._tube is None:
                opened["n"] += 1
                s._tube = FakeTube()
                s._t0 = s.clock()
            return s
        s.open = fake_open
        return s, opened

    def test_send_auto_opens(self):
        s, opened = self._session()
        self.assertIsNone(s._tube)
        n = s.send(b"abc")                 # no explicit open()
        self.assertEqual(n, 3)
        self.assertEqual(opened["n"], 1)
        self.assertEqual(s._tube.sent, b"abc")

    def test_recv_auto_opens_once(self):
        s, opened = self._session()
        self.assertEqual(s.recv(timeout=1), b"hello")
        s.recv(timeout=1)
        self.assertEqual(opened["n"], 1)   # opened exactly once, not per-recv

    def test_closed_session_does_not_auto_open(self):
        s, opened = self._session()
        s.close()
        with self.assertRaises(S.SessionError):
            s.send(b"x")
        self.assertEqual(opened["n"], 0)


@unittest.skipUnless(sandbox.image_available(PWN_IMAGE), f"{PWN_IMAGE} not present")
class OwnPortService(unittest.TestCase):
    """A target that binds its OWN port (manifest binds_port) is run directly as the service uid and
    reached by the agent on that port, instead of the stdio forwarder."""

    def test_binds_own_port(self):
        with tempfile.TemporaryDirectory() as run_s, tempfile.TemporaryDirectory() as dep_s:
            dep = Path(dep_s)
            (dep / "tree").mkdir()
            target = dep / "tree" / "target"
            target.write_text(textwrap.dedent("""\
                #!/usr/bin/env python3
                import socket, os
                srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("127.0.0.1", 12345)); srv.listen(8)
                while True:                       # loop like a real own-port server
                    c, _ = srv.accept()
                    c.sendall(b"OWNPORT:" + open("/flag.txt").read().encode())
                    c.close()
            """))
            target.chmod(0o755)
            manifest = {"target_rel": "target", "run_cwd_rel": ".", "lib_mode": "none",
                        "interp": None, "flag_decoys": [], "binds_port": 12345}
            (dep / "deploy.json").write_text(json.dumps(manifest))
            # /input is mounted ro and the container root has no CAP_DAC_OVERRIDE: make it traversable.
            os.chmod(dep, 0o755)
            os.chmod(dep / "tree", 0o755)
            os.chmod(dep / "deploy.json", 0o644)
            exp = ("import os, session\n"
                   "s = session.Session(remote=('127.0.0.1', 12345), log_dir='/work/s')\n"
                   "print(s.recvall(timeout=5))\n")
            FLAG = "flag{own_port_ok}"
            res = pwn_service.run(run_s, dep, "target", FLAG, exp, manifest=manifest,
                                  exp_id="t-ownport", image=PWN_IMAGE, wall_s=60)
            self.assertIn("OWNPORT:", res["stdout"])
            self.assertIn(FLAG, res["stdout"])     # reached over the target's own port


if __name__ == "__main__":
    unittest.main()
