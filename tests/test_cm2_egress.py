"""Phase CM2: scoped target-only egress (contest mode) acceptance tests.

Proves with a dummy local server that the DECLARED target is reachable and any
NON-target egress is denied — both at the broker allowlist layer (always) and, when
docker is present, at the container sealing layer (`--internal` net has no external
route). Bench isolation (`--network none`) and the governance hashes stay unchanged.
"""
import hashlib
import socket
import subprocess
import threading
import time
import unittest
import uuid
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools import contest_net as cn              # noqa: E402
from orchestrator import mode as mode_mod        # noqa: E402


# ---- dummy local servers -------------------------------------------------------

class EchoServer:
    """Accept one+ connections and echo back whatever is sent (the 'target')."""
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", 0))
        self.s.listen(8)
        self.address = self.s.getsockname()
        self.conns = 0
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.s.settimeout(0.25)
        while not self._stop.is_set():
            try:
                c, _ = self.s.accept()
            except (socket.timeout, OSError):
                continue
            self.conns += 1
            threading.Thread(target=self._echo, args=(c,), daemon=True).start()

    def _echo(self, c):
        try:
            c.settimeout(2)
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def stop(self):
        self._stop.set()
        try:
            self.s.close()
        except OSError:
            pass


def _read_line(sock, timeout=3):
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf and len(buf) < 256:
        d = sock.recv(64)
        if not d:
            break
        buf += d
    return buf.split(b"\n", 1)[0]


def _ask_broker(broker_addr, host, port, payload=b""):
    """Speak the broker protocol; return (status_bytes, echoed_bytes)."""
    s = socket.create_connection(broker_addr, timeout=3)
    try:
        s.sendall(f"{host} {port}\n".encode())
        status = _read_line(s)
        echoed = b""
        if status == b"OK" and payload:
            s.sendall(payload)
            s.settimeout(3)
            echoed = s.recv(len(payload))
        return status, echoed
    finally:
        s.close()


# ---- target parsing + policy ---------------------------------------------------

class TestParseTarget(unittest.TestCase):
    def test_nc(self):
        self.assertEqual(cn.parse_target("nc 3.34.202.171 8301"), [("3.34.202.171", 8301)])

    def test_nc_backticked(self):
        self.assertEqual(cn.parse_target("`nc 3.34.202.171 8301`"), [("3.34.202.171", 8301)])

    def test_http_with_port(self):
        self.assertEqual(cn.parse_target("http://3.34.205.142:8000/img"),
                         [("3.34.205.142", 8000)])

    def test_https_default_port(self):
        self.assertEqual(cn.parse_target("https://ctf.example.com"),
                         [("ctf.example.com", 443)])

    def test_bare_host_port(self):
        self.assertEqual(cn.parse_target("54.117.161.66:31337"), [("54.117.161.66", 31337)])

    def test_host_space_port(self):
        self.assertEqual(cn.parse_target("host 8301"), [("host", 8301)])

    def test_multi_and_dedup(self):
        got = cn.parse_target("nc a 1\nnc a 1, http://b:2")
        self.assertEqual(got, [("a", 1), ("b", 2)])

    def test_junk(self):
        self.assertEqual(cn.parse_target("just read the source"), [])


class TestPolicy(unittest.TestCase):
    def test_allow_deny(self):
        p = cn.EgressPolicy([("1.2.3.4", 31337)])
        self.assertTrue(p.is_allowed("1.2.3.4", 31337))
        self.assertFalse(p.is_allowed("1.2.3.4", 80))        # wrong port denied
        self.assertFalse(p.is_allowed("9.9.9.9", 31337))     # wrong host denied

    def test_from_declaration(self):
        p = cn.EgressPolicy.from_declaration("nc 1.2.3.4 31337")
        self.assertTrue(p.is_allowed("1.2.3.4", 31337))

    def test_not_blanket(self):
        # an empty/garbage declaration must NOT open everything
        p = cn.EgressPolicy.from_declaration("read the binary")
        self.assertFalse(bool(p))
        self.assertFalse(p.is_allowed("1.2.3.4", 80))


class TestModeEgress(unittest.TestCase):
    def test_bench_is_network_none(self):
        self.assertIsNone(cn.egress_for_mode(mode_mod.BENCH, "nc 1.2.3.4 31337"))

    def test_contest_scoped(self):
        pol = cn.egress_for_mode(mode_mod.CONTEST, "nc 1.2.3.4 31337")
        self.assertIsInstance(pol, cn.EgressPolicy)
        self.assertEqual(pol.as_dict(), {"default": "deny", "allow": ["1.2.3.4:31337"]})


# ---- broker allowlist e2e (dummy local server; always runs) --------------------

class TestBrokerEgressE2E(unittest.TestCase):
    def setUp(self):
        self.target = EchoServer()
        self.nontarget = EchoServer()     # a server the run must NOT be able to reach
        th, tp = self.target.address
        policy = cn.EgressPolicy([(th, tp)])
        self.broker = cn.EgressBroker(policy).start()

    def tearDown(self):
        self.broker.stop()
        self.target.stop()
        self.nontarget.stop()

    def test_declared_target_reachable(self):
        status, echoed = _ask_broker(self.broker.address, *self.target.address, payload=b"ping")
        self.assertEqual(status, b"OK")
        self.assertEqual(echoed, b"ping")
        self.assertIn(self.target.address, self.broker.allowed_dials)

    def test_nontarget_denied_and_never_dialled(self):
        nh, np_ = self.nontarget.address
        before = self.nontarget.conns
        status, _ = _ask_broker(self.broker.address, nh, np_, payload=b"ping")
        self.assertEqual(status, b"DENIED")
        # give any (erroneous) async dial a chance to land, then prove it never did
        time.sleep(0.3)
        self.assertEqual(self.nontarget.conns, before, "non-target was contacted!")
        self.assertIn((nh, np_), self.broker.denials)
        self.assertNotIn((nh, np_), self.broker.allowed_dials)


# ---- container sealing e2e (docker only) ---------------------------------------

@unittest.skipUnless(cn.docker_available(), "docker not available")
class TestContainerSealingE2E(unittest.TestCase):
    """A container on a per-run `--internal` network can reach an IN-NET target but
    has NO route to any external (non-target) host — target-only by construction."""

    IMAGE = "python:3.12-slim-bookworm"

    @classmethod
    def setUpClass(cls):
        have = subprocess.run(["docker", "image", "inspect", cls.IMAGE],
                              capture_output=True).returncode == 0
        if not have:
            raise unittest.SkipTest(f"image {cls.IMAGE} not present locally")
        cls.run_id = "cm2" + uuid.uuid4().hex[:8]
        cls.net = cn.network_name(cls.run_id)
        subprocess.run(cn.create_internal_network_argv(cls.run_id), check=True,
                       capture_output=True)
        # in-net dummy target: a trivial TCP echo on :9000 (stands in for the broker's
        # exposed target endpoint reachable from inside the sealed network)
        srv = ("import socket as s\n"
               "x=s.socket();x.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR,1)\n"
               "x.bind(('0.0.0.0',9000));x.listen(4)\n"
               "while 1:\n c,_=x.accept();d=c.recv(100);c.sendall(d);c.close()\n")
        cls.target_name = f"cm2tgt_{cls.run_id}"
        subprocess.run(["docker", "run", "-d", "--rm", "--name", cls.target_name,
                        "--network", cls.net, cls.IMAGE, "python3", "-c", srv],
                       check=True, capture_output=True)
        time.sleep(1.0)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["docker", "rm", "-f", cls.target_name], capture_output=True)
        subprocess.run(cn.remove_network_argv(cls.run_id), capture_output=True)

    def _probe(self, host, port):
        """Run an isolated container that tries to TCP-connect host:port; prints RESULT."""
        code = (f"import socket\n"
                f"try:\n"
                f"  c=socket.create_connection(('{host}',{port}),timeout=4)\n"
                f"  c.sendall(b'hi');r=c.recv(10);print('OK',r)\n"
                f"except Exception as e:\n  print('BLOCKED',type(e).__name__)\n")
        argv = ["docker", "run", "--rm", "--network", self.net,
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--read-only", "--user", "65534:65534",
                self.IMAGE, "python3", "-c", code]
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return out.stdout.strip()

    def test_in_net_target_reachable(self):
        self.assertIn("OK", self._probe(self.target_name, 9000))

    def test_external_nontarget_blocked(self):
        # 198.51.100.7 is TEST-NET-2 (RFC 5737): no route from an internal docker net
        self.assertIn("BLOCKED", self._probe("198.51.100.7", 80))

    def test_cfg_network_override_is_runtime_only(self):
        base = {"container": {"network": "none", "image": self.IMAGE}}
        cfg = cn.container_network_cfg(base["container"], self.run_id)
        self.assertEqual(cfg["network"], self.net)
        self.assertEqual(base["container"]["network"], "none")   # original untouched


# ---- governance untouched ------------------------------------------------------

class TestGovernanceUntouched(unittest.TestCase):
    def test_seven_files_hash_invariant(self):
        baseline = (PROJECT_ROOT / "growth" / "governance_baseline.txt").read_text().splitlines()
        for line in baseline:
            line = line.strip()
            if not line:
                continue
            want, rel = line.split()[0], line.split()[-1]
            got = hashlib.sha256((PROJECT_ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"governance file changed: {rel}")


if __name__ == "__main__":
    unittest.main()
