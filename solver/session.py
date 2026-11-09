"""Interactive session layer for pwn solving — a stateful tube to a running
process (open / send / recv / close), used for the send -> leak -> re-send loop
that single-shot run_tool cannot express.

Design constraints (deliberately separate from the single-shot tool path):
  * Runs INSIDE the container (untrusted, --network none). The target is a LOCAL
    process started with pwntools `process()`; no network is ever used. This file
    is copied into the jail at run time by PwnHarness, not baked into the image,
    so it stays iterable.
  * Byte-safe: every send/recv value is raw `bytes` (payloads are non-UTF-8). The
    transcript logs a capped hex+repr preview; the full bytes of an over-cap chunk
    spill to an artifact file, never into the inline log.
  * Bounded: a per-session wall-clock budget and a total-received-byte cap (the
    HackSynth 250/500 lesson — an unbounded `recv` on a chatty target can bury the
    reasoner). Hitting either raises; it is not a silent truncation of state.
  * No zombies: the child is always killed and reaped (context manager + close()).

The transcript (JSONL) and spill artifacts are written under a caller-supplied
directory that lives in /work, so they persist to the host jail and surface as
experiment artifacts. Records mirror the run_tool schema vocabulary
(execution_status / observation / reproducibility / sandbox_profile) at the
session level so a session experiment logs consistently with a single-shot one.
"""
import json
import socket
import time
from pathlib import Path

# pwntools is imported lazily inside open() so this module (and its pure helpers)
# import cleanly on a host without pwntools, for unit tests.


def _pwntools_available():
    try:
        import pwn  # noqa: F401
        return True
    except Exception:
        return False

DEFAULT_WALL_S = 30.0
DEFAULT_OUTPUT_CAP = 262144          # 256 KiB total recv per session
INLINE_PREVIEW = 512                 # bytes shown inline per record; rest spills


# ---- pure helpers (host-unit-testable, no pwntools) --------------------------

def safe_repr(data: bytes, limit: int = INLINE_PREVIEW):
    """A bounded, byte-safe preview of `data`.

    Returns {repr, hex, len, truncated}: `repr`/`hex` cover at most the first
    `limit` bytes; `len` is the true length; `truncated` says bytes were dropped
    from the preview (the full bytes are spilled separately by the caller).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("session I/O must be bytes")
    data = bytes(data)
    head = data[:limit]
    return {"repr": repr(head), "hex": head.hex(), "len": len(data),
            "truncated": len(data) > limit}


class OutputBudget:
    """Accumulates total received bytes and enforces a hard cap."""

    def __init__(self, cap=DEFAULT_OUTPUT_CAP):
        self.cap = cap
        self.used = 0

    def add(self, n):
        self.used += n
        return self.used <= self.cap

    @property
    def remaining(self):
        return max(0, self.cap - self.used)

    def would_exceed(self, n):
        return self.used + n > self.cap


def interaction_record(seq, op, direction, data, budget, spill_ref=None, note=None):
    """One transcript entry. `direction` is 'send' | 'recv' | None (control op)."""
    rec = {"seq": seq, "op": op, "direction": direction, "t": round(time.time(), 6)}
    if data is not None:
        prev = safe_repr(data)
        rec.update({"bytes": prev["len"], "preview_repr": prev["repr"],
                    "preview_hex": prev["hex"], "preview_truncated": prev["truncated"]})
        if spill_ref:
            rec["spill_ref"] = spill_ref
    if budget is not None:
        rec["output_used"] = budget.used
    if note:
        rec["note"] = note
    return rec


# ---- exceptions --------------------------------------------------------------

class SessionError(Exception):
    pass


class SessionWallTimeout(SessionError):
    pass


class SessionOutputCap(SessionError):
    pass


class BrokerRefused(SessionError):
    """The CM2 egress broker refused the tunnel to the requested target.

    This is the [cyber] egress gate firing: the dial was outside the per-run allowlist
    and was logged + closed, never worked around. The caller surfaces it honestly."""


# ---- pwntools-free socket tube (host-side contest egress path) ---------------
# In-container pwn solving uses pwntools (process/remote). The INTEGRATED contest
# path runs host-side and reaches the target through the EgressBroker, where pwntools
# is typically not installed — so a minimal raw-socket tube provides the same
# Session-facing surface (send/recv/recvuntil/recvline/recvall/close/poll). It is a
# transport only; all budget/wall/transcript discipline stays in Session.

class _SocketTube:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        self.pid = None

    def _fill(self, timeout):
        """Pull one chunk. Returns the chunk, b'' on timeout/no-data, or None on EOF."""
        try:
            self.sock.settimeout(timeout if timeout and timeout > 0 else (None if timeout is None else 0.05))
            chunk = self.sock.recv(4096)
        except socket.timeout:
            return b""
        except OSError:
            return None
        if not chunk:
            return None
        self.buf += chunk
        return chunk

    def send(self, data):
        self.sock.sendall(bytes(data))

    def recv(self, numb=4096, timeout=None):
        if not self.buf:
            self._fill(timeout)
        out, self.buf = self.buf[:numb], self.buf[numb:]
        return out

    def recvuntil(self, delim, timeout=None, drop=False):
        delim = bytes(delim)
        end = None if timeout is None else time.monotonic() + float(timeout)
        while delim not in self.buf:
            rem = None if end is None else max(0.0, end - time.monotonic())
            if end is not None and rem <= 0:
                break
            r = self._fill(rem)
            if r is None:                 # EOF
                break
            if r == b"" and end is None:  # no data and no deadline -> give up
                break
        idx = self.buf.find(delim)
        if idx == -1:
            out, self.buf = self.buf, b""
            return out
        cut = idx + len(delim)
        out, self.buf = self.buf[:cut], self.buf[cut:]
        return out[:idx] if drop else out

    def recvline(self, timeout=None, keepends=True):
        out = self.recvuntil(b"\n", timeout=timeout)
        if not keepends and out.endswith(b"\n"):
            out = out[:-1]
        return out

    def recvall(self, timeout=None):
        end = None if timeout is None else time.monotonic() + float(timeout)
        while True:
            rem = None if end is None else max(0.0, end - time.monotonic())
            if end is not None and rem <= 0:
                break
            r = self._fill(rem)
            if r is None:                 # EOF
                break
            if r == b"":                  # timeout with connection still open
                break
        out, self.buf = self.buf, b""
        return out

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def poll(self, block=False):
        return None


# ---- the session ------------------------------------------------------------

class Session:
    """A stateful tube to one local process, with a transcript and hard limits.

    Use as a context manager so the child is always reaped:
        with Session(["./vuln"], log_dir="/work/sess") as s:
            s.recvuntil(b"flag:")
            s.send(payload)
            leak = s.recvline()
    """

    def __init__(self, argv=None, log_dir=None, cwd=None, env=None, aslr=False,
                 remote=None, broker=None, connect_timeout=5,
                 wall_s=DEFAULT_WALL_S, output_cap=DEFAULT_OUTPUT_CAP, clock=time.monotonic):
        # Either launch a local process (argv) or connect to a loopback service (remote=(host, port)).
        # remote mode is used by the pwn-service boundary: the target runs as a different uid and is
        # reachable only over 127.0.0.1, so the session drives it as a tube, same send/recv API.
        #
        # broker=(host, port): CM9 contest path. The tube is opened THROUGH the CM2
        # EgressBroker — it dials the broker, sends the "HOST PORT\n" request, and only
        # proceeds on an "OK" (a refusal raises BrokerRefused; the [cyber] egress gate is
        # not worked around). Used with remote= to reach the declared external target.
        self.remote = tuple(remote) if remote else None
        self.broker = tuple(broker) if broker else None
        self._connect_timeout = connect_timeout
        self.argv = list(argv) if argv else None
        if (self.argv is None) == (self.remote is None):
            raise ValueError("Session needs exactly one of argv= or remote=")
        if self.broker is not None and self.remote is None:
            raise ValueError("broker= requires remote= (the target to tunnel to)")
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.cwd = cwd
        self.env = env
        self.aslr = aslr
        self.wall_s = wall_s
        self.budget = OutputBudget(output_cap)
        self.clock = clock
        self._t0 = None
        self._seq = 0
        self._spill = 0
        self._tube = None
        self.closed = False
        self.transcript_path = self.log_dir / "session.jsonl"
        self._tf = open(self.transcript_path, "a", encoding="utf-8")

    # -- lifecycle --
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def open(self):
        if self._tube is not None:        # idempotent: `with` + a later auto-open must not double-open
            return self
        if self.closed:
            raise SessionError("session is closed")
        # Host-side contest egress path: a broker tunnel, or a remote with no pwntools,
        # is driven by the pwntools-free socket tube. The in-container pwntools path
        # (local process / direct remote where pwntools exists) is unchanged.
        if self.remote is not None and (self.broker is not None or not _pwntools_available()):
            self._t0 = self.clock()
            try:
                self._tube = self._open_socket_tube()
            except Exception:
                # a failed open (e.g. the [cyber] egress gate refusing the dial) must not
                # leak the transcript file handle; close it and mark the session done.
                self.closed = True
                try:
                    self._tf.close()
                except Exception:
                    pass
                raise
            note = {"remote": list(self.remote),
                    "broker": list(self.broker) if self.broker else None, "transport": "socket"}
            self._log(interaction_record(self._next(), "open", None, None, self.budget, note=note))
            return self
        from pwn import process, remote, context    # lazy: only inside the container
        context.log_level = "error"
        self._t0 = self.clock()
        if self.remote is not None:
            self._tube = remote(self.remote[0], int(self.remote[1]))
            note = {"remote": list(self.remote)}
        else:
            self._tube = process(self.argv, cwd=self.cwd, env=self.env, aslr=self.aslr)
            note = {"argv": self.argv, "aslr": self.aslr, "pid": getattr(self._tube, "pid", None)}
        self._log(interaction_record(self._next(), "open", None, None, self.budget, note=note))
        return self

    def _open_socket_tube(self):
        """Open a raw-socket tube to the target, through the broker when one is set.

        The broker handshake is the same one the EgressBroker speaks: send "HOST PORT\\n",
        read a status line, proceed only on "OK". Anything else is the [cyber] egress
        gate refusing the dial -> BrokerRefused (logged by the caller, never bypassed)."""
        host, port = self.remote[0], int(self.remote[1])
        if self.broker is not None:
            bhost, bport = self.broker[0], int(self.broker[1])
            sock = socket.create_connection((bhost, bport), timeout=self._connect_timeout)
            sock.sendall(f"{host} {port}\n".encode())
            sock.settimeout(self._connect_timeout)
            line = b""
            while b"\n" not in line and len(line) < 64:
                c = sock.recv(16)
                if not c:
                    break
                line += c
            status = line.split(b"\n", 1)[0].decode("ascii", "replace")
            if status != "OK":
                try:
                    sock.close()
                except OSError:
                    pass
                raise BrokerRefused(status or "no_status")
            return _SocketTube(sock)
        sock = socket.create_connection((host, port), timeout=self._connect_timeout)
        return _SocketTube(sock)

    # -- time / budget guards --
    def _elapsed(self):
        return self.clock() - self._t0 if self._t0 is not None else 0.0

    def _check_wall(self, op):
        if self._elapsed() > self.wall_s:
            self._log(interaction_record(self._next(), op, None, None, self.budget,
                                         note="wall_timeout"))
            raise SessionWallTimeout(f"session wall budget {self.wall_s}s exceeded at {op}")

    def _account_recv(self, op, data):
        if self.budget.would_exceed(len(data)):
            self._spill_and_log(op, "recv", data, note="output_cap")
            self.budget.add(len(data))
            raise SessionOutputCap(f"session output cap {self.budget.cap}B exceeded at {op}")
        self.budget.add(len(data))
        self._spill_and_log(op, "recv", data)
        return data

    # -- send --
    def send(self, data: bytes):
        self._require_open()
        self._check_wall("send")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("send() requires bytes")
        self._tube.send(bytes(data))
        self._spill_and_log("send", "send", bytes(data))
        return len(data)

    def sendline(self, data: bytes = b""):
        return self.send(bytes(data) + b"\n")

    # -- recv --
    def recv(self, numb=4096, timeout=None):
        self._require_open()
        self._check_wall("recv")
        data = self._tube.recv(numb=numb, timeout=self._timeout(timeout))
        return self._account_recv("recv", data)

    def recvuntil(self, delim: bytes, timeout=None, drop=False):
        self._require_open()
        self._check_wall("recvuntil")
        data = self._tube.recvuntil(bytes(delim), timeout=self._timeout(timeout), drop=drop)
        return self._account_recv("recvuntil", data)

    def recvline(self, timeout=None, keepends=True):
        self._require_open()
        self._check_wall("recvline")
        data = self._tube.recvline(timeout=self._timeout(timeout), keepends=keepends)
        return self._account_recv("recvline", data)

    def recvall(self, timeout=None):
        """Drain until EOF, but never past the output cap (raises if it would)."""
        self._require_open()
        self._check_wall("recvall")
        data = self._tube.recvall(timeout=self._timeout(timeout))
        return self._account_recv("recvall", data)

    def interactive_round(self, payload: bytes, until: bytes = None, recv_bytes=4096, timeout=None):
        """One send -> recv step, the unit of the leak/re-send loop."""
        self.send(payload)
        if until is not None:
            return self.recvuntil(until, timeout=timeout)
        return self.recv(recv_bytes, timeout=timeout)

    # -- close / cleanup --
    def close(self):
        if self.closed:
            return
        self.closed = True
        tube = self._tube
        if tube is not None:
            try:
                tube.close()                 # pwntools kills + reaps the child
            except Exception:
                pass
            try:
                if getattr(tube, "poll", None) is not None:
                    tube.poll(block=False)   # reap any remaining zombie
            except Exception:
                pass
        self._log(interaction_record(self._next(), "close", None, None, self.budget,
                                     note={"elapsed_s": round(self._elapsed(), 3),
                                           "output_used": self.budget.used}))
        try:
            self._tf.close()
        except Exception:
            pass

    # -- internals --
    def _timeout(self, t):
        # cap any per-call timeout by the remaining wall budget
        remaining = max(0.0, self.wall_s - self._elapsed())
        if t is None:
            return remaining
        return min(float(t), remaining)

    def _require_open(self):
        if self.closed:
            raise SessionError("session is closed")
        if self._tube is None:
            # auto-open on first send/recv: using a Session without .open()/`with` was a Phase 14
            # footgun that cost at least one validated solve. Opening here is safe and idempotent.
            self.open()

    def _next(self):
        self._seq += 1
        return self._seq

    def _spill_and_log(self, op, direction, data, note=None):
        prev = safe_repr(data)
        spill_ref = None
        if prev["truncated"]:
            self._spill += 1
            name = f"spill_{self._spill:03d}_{op}.bin"
            (self.log_dir / name).write_bytes(bytes(data))
            spill_ref = name
        self._log(interaction_record(self._next(), op, direction, data, self.budget,
                                     spill_ref=spill_ref, note=note))

    def _log(self, rec):
        self._tf.write(json.dumps(rec, sort_keys=True) + "\n")
        self._tf.flush()
