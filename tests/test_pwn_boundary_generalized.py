"""Phase 33 — pwn-service boundary generalization regression tests.

Proves the three deployment-gap fixes on SYNTHETIC mini-services (vault-free, throwaway
flag), each paired with the anti-cheat invariant that the AGENT uid still cannot read the
flag file directly:

  companion : a service that CREATES a runtime companion file in its cwd (the horrorscope
              gap) now works because the cwd is service-owned/writable.
  passwd    : a service that calls getpwuid(geteuid()) (the GNUstep gap) now survives
              because the boundary writes a minimal /etc/passwd entry for the service uid.
  forking   : a forking server that binds its OWN port and sends a 32-byte banner (the
              Salt gap) now relays the banner because binds_port (incl. 0) routes to a
              direct run instead of the stdio forwarder.

All require the pwn image; skipped if absent.
"""
import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from tools import pwn_service, sandbox  # noqa: E402

PWN_IMAGE = "ctfagent-pwn:0.1"
FLAG = "flag{synthetic_boundary_probe}"


def _deploy(tmp, target_name, target_src, binds_port):
    """Build a synthetic /input deploy dir: deploy.json + tree/<target> (executable script)."""
    inp = Path(tmp) / "input"
    tree = inp / "tree"
    tree.mkdir(parents=True)
    t = tree / target_name
    t.write_text(target_src)
    t.chmod(0o755)
    manifest = {
        "target_rel": target_name, "run_cwd_rel": ".", "lib_mode": "none", "interp": None,
        "flag_decoys": [], "binds_port": binds_port, "public_files": [target_name],
    }
    (inp / "deploy.json").write_text(json.dumps(manifest))
    return str(inp), manifest


def _run(tmp, target_name, target_src, agent_code, binds_port=None, wall=90):
    inp, manifest = _deploy(tmp, target_name, target_src, binds_port)
    run_dir = Path(tmp) / "run"
    run_dir.mkdir()
    return pwn_service.run(run_dir, inp, target_name, FLAG, agent_code,
                           manifest=manifest, image=PWN_IMAGE, wall_s=wall, write_record=False)


# agent connects to 127.0.0.1:$PORT, optionally sends a line, prints what it receives
_AGENT_CONNECT = textwrap.dedent('''
    import os, socket, time
    PORT = int(os.environ.get("PORT", "9999"))
    data = b""
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=1.0); break
        except OSError:
            time.sleep(0.1)
    else:
        print("NOCONNECT"); raise SystemExit(0)
    try:
        s.sendall(b"go\\n")
        s.settimeout(2.0)
        for _ in range(5):
            try:
                chunk = s.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    print("RECV_LEN", len(data))
    print("RECV", data.decode("latin1"))
''')

# anti-cheat: the agent tries to read the staged flag file directly -> must fail
_AGENT_READ_FLAG = textwrap.dedent('''
    import os
    paths = ["/srv/tree/flag.txt", "/srv/flag.txt", "/srv/tree/flag", "/flag.txt", "flag.txt"]
    for p in paths:
        try:
            print("READ", p, open(p).read())
        except OSError as e:
            print("DENIED", p, e.errno)
''')


@unittest.skipUnless(sandbox.image_available(PWN_IMAGE), f"{PWN_IMAGE} not present")
class BoundaryGeneralization(unittest.TestCase):
    def test_companion_writable_cwd(self):
        # service CREATES a runtime companion in cwd (fails on a root-owned cwd); then serves the
        # flag over stdio only if that succeeded.
        target = ('#!/usr/bin/env python3\n'
                  'import sys\n'
                  'try:\n'
                  '    open("runtime_cookie.txt", "w").write("ok")\n'
                  'except OSError:\n'
                  '    sys.stdout.write("NOCWD\\n"); sys.stdout.flush(); sys.exit(3)\n'
                  'sys.stdin.readline()\n'
                  'try:\n'
                  '    f = open("flag.txt").read().strip()\n'
                  'except OSError:\n'
                  '    f = "NOFLAG"\n'
                  'sys.stdout.write(f + "\\n"); sys.stdout.flush()\n')
        with tempfile.TemporaryDirectory() as tmp:
            res = _run(tmp, "svc.py", target, _AGENT_CONNECT, binds_port=None)
            self.assertEqual(res["execution_status"], "ok", res["stderr"][:400])
            self.assertNotIn("NOCWD", res["stdout"])
            self.assertIn(FLAG, res["stdout"])

    def test_passwd_getpwuid_survives(self):
        # service aborts (GNUstep-style) if its uid has no /etc/passwd entry; the boundary now
        # provides one, so it survives and serves the flag.
        target = ('#!/usr/bin/env python3\n'
                  'import os, sys, pwd\n'
                  'try:\n'
                  '    pwd.getpwuid(os.geteuid())\n'
                  'except KeyError:\n'
                  '    sys.stdout.write("NOPWD\\n"); sys.stdout.flush(); sys.exit(3)\n'
                  'sys.stdin.readline()\n'
                  'sys.stdout.write(open("flag.txt").read().strip() + "\\n"); sys.stdout.flush()\n')
        with tempfile.TemporaryDirectory() as tmp:
            res = _run(tmp, "svc.py", target, _AGENT_CONNECT, binds_port=None)
            self.assertEqual(res["execution_status"], "ok", res["stderr"][:400])
            self.assertNotIn("NOPWD", res["stdout"])
            self.assertIn(FLAG, res["stdout"])

    def test_forking_ownport_banner(self):
        # forking server that binds its OWN port and sends a 32-byte banner on connect. binds_port=0
        # ("binds, port unknown") must route to a DIRECT run so the banner reaches the agent.
        target = ('#!/usr/bin/env python3\n'
                  'import os, sys, socket, signal\n'
                  'PORT = int(os.environ.get("PORT", "9999"))\n'
                  'signal.signal(signal.SIGCHLD, signal.SIG_IGN)\n'
                  's = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n'
                  's.bind(("127.0.0.1", PORT)); s.listen(8)\n'
                  'while True:\n'
                  '    try:\n'
                  '        c, _ = s.accept()\n'
                  '    except OSError:\n'
                  '        break\n'
                  '    if os.fork() == 0:\n'
                  '        s.close()\n'
                  '        c.sendall(b"B" * 32)\n'
                  '        try:\n'
                  '            c.recv(16)\n'
                  '        except OSError:\n'
                  '            pass\n'
                  '        c.sendall(open("flag.txt", "rb").read())\n'
                  '        os._exit(0)\n'
                  '    c.close()\n')
        with tempfile.TemporaryDirectory() as tmp:
            res = _run(tmp, "srv.py", target, _AGENT_CONNECT, binds_port=0)
            self.assertEqual(res["execution_status"], "ok", res["stderr"][:400])
            self.assertIn("B" * 32, res["stdout"])   # the 32-byte handshake was relayed
            self.assertIn(FLAG, res["stdout"])        # and the flag followed

    def test_anticheat_flag_unreadable_by_agent(self):
        # with the SAME generalized boundary, the agent uid still cannot read the flag file directly.
        target = ('#!/usr/bin/env python3\n'
                  'import sys\n'
                  'sys.stdin.readline()\n'
                  'sys.stdout.write(open("flag.txt").read().strip() + "\\n"); sys.stdout.flush()\n')
        with tempfile.TemporaryDirectory() as tmp:
            res = _run(tmp, "svc.py", target, _AGENT_READ_FLAG, binds_port=None)
            self.assertEqual(res["execution_status"], "ok", res["stderr"][:400])
            self.assertNotIn(FLAG, res["stdout"])             # never obtained by direct read
            self.assertIn("DENIED", res["stdout"])            # every direct open was denied/missing
            self.assertNotIn("READ /srv", res["stdout"])      # no successful read of a staged flag


if __name__ == "__main__":
    unittest.main()
