"""Phase CM2: scoped target-only egress for CONTEST mode.

"target-only" is NOT blanket networking. For each run the challenge declares exactly
one (or a few) target endpoint(s) — `nc 1.2.3.4 31337`, `http://host:8000`, a bare
`host:port` — and the solving environment may reach ONLY those. Every other egress is
denied (exfil + discipline). Bench mode is unaffected: it stays `--network none`.

Two layers, one allowlist:

  1. EgressPolicy — the per-run allowlist (default deny). The single source of truth
     for what may be dialled. Pure data; trivially testable.

  2. EgressBroker — a tiny stdlib CONNECT-style proxy that enforces the policy: a
     client asks it for "HOST PORT"; allowed -> it dials and pumps bytes both ways;
     denied -> it LOGS the refusal and closes, never dialling. There is no bypass
     path ([cyber] weaponization/egress gate: blocked -> logged, not worked around).

Docker deployment (built here as data; executed only where docker exists):
  - the solving container joins a per-run `docker network create --internal` net:
    an internal net has no NAT to the outside, so the container has ZERO external
    reachability BY CONSTRUCTION — it cannot reach any non-target host at all.
  - the broker runs as a sidecar bridging the internal net to the outside, dialling
    only the declared target. The container's single route out is that broker.
  - ALL other isolation is inherited UNCHANGED from the governance container profile
    (non-root, --cap-drop ALL, no-new-privileges, read-only root, only /work rw); we
    override only the `network` field of a RUNTIME COPY of the config — tools/sandbox.py
    and config/sandbox.json are never edited.

Stdlib only.
"""
import re
import shutil
import socket
import threading
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}


def parse_target(decl):
    """Parse a challenge target declaration into a list of (host, port) tuples.

    Accepts: 'nc 1.2.3.4 31337', 'http://host:8000/path', 'https://h', 'host:port',
    a bare 'host 8301', or several separated by comma/newline. Unparseable -> skipped.
    """
    if not decl:
        return []
    out = []
    for chunk in re.split(r"[,\n]+", str(decl)):
        chunk = chunk.strip().strip("`")
        if not chunk:
            continue
        # nc / ncat / connect style:  "nc HOST PORT"
        m = re.match(r"(?:nc|ncat|connect)\s+(\S+)\s+(\d+)\b", chunk, re.I)
        if m:
            out.append((m.group(1), int(m.group(2))))
            continue
        # URL style
        if "://" in chunk:
            u = urlsplit(chunk)
            if u.hostname:
                port = u.port or DEFAULT_PORTS.get((u.scheme or "").lower())
                if port:
                    out.append((u.hostname, int(port)))
            continue
        # bare host:port
        m = re.match(r"^([A-Za-z0-9._-]+):(\d+)$", chunk)
        if m:
            out.append((m.group(1), int(m.group(2))))
            continue
        # "host port"
        m = re.match(r"^([A-Za-z0-9._-]+)\s+(\d+)$", chunk)
        if m:
            out.append((m.group(1), int(m.group(2))))
            continue
    # de-dup, preserve order
    seen, uniq = set(), []
    for hp in out:
        if hp not in seen:
            seen.add(hp)
            uniq.append(hp)
    return uniq


class EgressPolicy:
    """A per-run allowlist of (host, port). Default deny for everything else."""

    def __init__(self, allow):
        self.allow = {(str(h), int(p)) for h, p in allow}

    @classmethod
    def from_declaration(cls, decl):
        return cls(parse_target(decl))

    def is_allowed(self, host, port):
        return (str(host), int(port)) in self.allow

    def as_dict(self):
        return {"default": "deny",
                "allow": sorted(f"{h}:{p}" for h, p in self.allow)}

    def __bool__(self):
        return bool(self.allow)

    def __repr__(self):
        return f"EgressPolicy(allow={sorted(self.allow)})"


class EgressBroker:
    """A localhost CONNECT-style allowlist proxy enforcing an EgressPolicy.

    Protocol: a client opens a TCP connection and sends a first line "HOST PORT\\n".
    If the policy allows it, the broker connects upstream and relays bytes both ways.
    If not, it appends to `.denials` and closes WITHOUT dialling anything.

    This is exactly what the docker sidecar runs; running it as a host process lets the
    scoped-egress property be proven end-to-end without docker.
    """

    def __init__(self, policy, host="127.0.0.1", connect_timeout=5):
        self.policy = policy
        self.denials = []           # [(host, port), ...] refused dials (the egress log)
        self.allowed_dials = []     # [(host, port), ...] dials actually made
        self._connect_timeout = connect_timeout
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, 0))
        self._srv.listen(16)
        self.address = self._srv.getsockname()      # (host, port) to point clients at
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._lock = threading.Lock()

    def start(self):
        self._thread.start()
        return self

    def _serve(self):
        self._srv.settimeout(0.25)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(self._connect_timeout)
            req = b""
            while b"\n" not in req and len(req) < 256:
                chunk = conn.recv(64)
                if not chunk:
                    return
                req += chunk
            line = req.split(b"\n", 1)[0].decode("ascii", "replace").strip()
            parts = line.split()
            if len(parts) != 2 or not parts[1].isdigit():
                return
            host, port = parts[0], int(parts[1])
            if not self.policy.is_allowed(host, port):
                with self._lock:
                    self.denials.append((host, port))   # [cyber] logged, not bypassed
                try:
                    conn.sendall(b"DENIED\n")
                except OSError:
                    pass
                return
            with self._lock:
                self.allowed_dials.append((host, port))
            self._relay(conn, host, port)
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _relay(self, client, host, port):
        try:
            up = socket.create_connection((host, port), timeout=self._connect_timeout)
        except OSError:
            try:
                client.sendall(b"UPSTREAM_FAIL\n")
            except OSError:
                pass
            return
        try:
            client.sendall(b"OK\n")   # tell the CLIENT the tunnel is open, then pump raw
        except OSError:
            up.close()
            return
        self._pump(client, up)

    @staticmethod
    def _pump(a, b):
        """Relay bytes both ways until BOTH directions EOF. On one side closing, the
        other direction is half-closed (SHUT_WR) so buffered data is fully flushed — a
        fast-closing upstream (e.g. an HTTP/1.0 server) must not truncate the response."""
        def copy(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)   # signal EOF to dst, flushing its buffer
                except OSError:
                    pass

        t1 = threading.Thread(target=copy, args=(a, b), daemon=True)
        t2 = threading.Thread(target=copy, args=(b, a), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass


# ---- docker wiring (data; executed only where docker exists) -------------------

def docker_available():
    return shutil.which("docker") is not None


def network_name(run_id):
    return f"ctfnet_{run_id}"


def create_internal_network_argv(run_id):
    """`docker network create --internal <name>` — an internal net has NO route to the
    outside, so a container on it alone cannot reach ANY non-target host."""
    return ["docker", "network", "create", "--internal", network_name(run_id)]


def remove_network_argv(run_id):
    return ["docker", "network", "rm", network_name(run_id)]


def container_network_cfg(base_cfg, run_id):
    """Return a RUNTIME COPY of the governance container config with only `network`
    repointed at the per-run internal net. tools/sandbox.py / config/sandbox.json are
    NEVER edited; sandbox.build_container_argv reads cfg['network'] at runtime."""
    import copy
    cfg = copy.deepcopy(base_cfg)
    cfg["network"] = network_name(run_id)
    return cfg


def egress_for_mode(mode, target_decl):
    """The egress plan for a run.

    contest -> an EgressPolicy scoped to the declared target(s) (default deny).
    bench   -> None, meaning `--network none` (unchanged blind isolation).
    """
    from orchestrator import mode as mode_mod
    if mode_mod.is_bench(mode):
        return None
    return EgressPolicy.from_declaration(target_decl)
