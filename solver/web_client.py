"""HTTP session layer for web solving — a stateful client to a running web app
(get / post / request), the HTTP analogue of solver/session.py's process tube.

Design constraints (deliberately parallel to session.py, HTTP instead of a byte tube):
  * Runs INSIDE the container (untrusted, --network none). The target is a LOCAL web app bound to
    127.0.0.1:PORT by the SERVICE uid behind the web-service boundary (tools/web_service.py); no
    external network is ever used. This file is copied into the jail at run time, not baked into the
    image, so it stays iterable.
  * Session-persistent: wraps one requests.Session, so cookies / auth state carry across requests
    (the login -> authenticated-request loop the single-shot tool path cannot express).
  * Byte-safe transcript: every request and response is logged as a capped hex+repr preview of the
    raw bytes (response bodies are not assumed to be UTF-8); an over-cap body spills to an artifact
    file, never inline. Uses session.py's safe_repr / interaction_record / OutputBudget verbatim so a
    web experiment logs with the same vocabulary as a pwn session.
  * Bounded: a per-session wall-clock budget and a total-received-byte cap (the same HackSynth lesson
    as session.py — a chatty endpoint must not bury the reasoner). Hitting either raises.
  * No leaks: context-manager safe; the underlying requests.Session is always closed.

The transcript (JSONL) and spill artifacts live under a caller-supplied log_dir in /work, so they
persist to the host jail and surface as experiment artifacts.
"""
import time
from pathlib import Path

# Reuse session.py's pure helpers + budget + record vocabulary. session.py imports pwntools only
# lazily inside Session.open(), so importing these names is safe in the pwntools-free web image.
# Dual import: inside the jail session.py sits beside this file on sys.path (/work/_lib); on the host
# it is the solver.session package module.
try:
    from session import (safe_repr, OutputBudget, interaction_record, SessionError,  # noqa: F401
                         DEFAULT_OUTPUT_CAP, INLINE_PREVIEW)
except ImportError:
    from solver.session import (safe_repr, OutputBudget, interaction_record, SessionError,  # noqa: F401
                               DEFAULT_OUTPUT_CAP, INLINE_PREVIEW)

DEFAULT_WALL_S = 60.0
DEFAULT_TIMEOUT = 15.0


class WebWallTimeout(SessionError):
    pass


class WebOutputCap(SessionError):
    pass


class WebClient:
    """A stateful HTTP client to one local web app, with a transcript and hard limits.

    Use as a context manager so the requests.Session is always closed:
        with WebClient("http://127.0.0.1:8080", log_dir="/work/web") as c:
            c.post("/login", data={"user": "guest", "pw": "guest"})
            r = c.get("/account?id=1")          # cookies carried from the login
            print(r.text)
    """

    def __init__(self, base_url, log_dir=None, wall_s=DEFAULT_WALL_S,
                 output_cap=DEFAULT_OUTPUT_CAP, timeout=DEFAULT_TIMEOUT, clock=time.monotonic):
        self.base_url = base_url.rstrip("/")
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.wall_s = wall_s
        self.budget = OutputBudget(output_cap)
        self.timeout = timeout
        self.clock = clock
        self._t0 = None
        self._seq = 0
        self._spill = 0
        self._sess = None
        self.closed = False
        self.transcript_path = self.log_dir / "web.jsonl"
        self._tf = open(self.transcript_path, "a", encoding="utf-8")

    # -- lifecycle --
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def open(self):
        if self._sess is not None:          # idempotent (mirrors Session.open)
            return self
        if self.closed:
            raise SessionError("web client is closed")
        import requests                      # lazy: only inside the container
        self._t0 = self.clock()
        self._sess = requests.Session()
        self._log(interaction_record(self._next(), "open", None, None, self.budget,
                                     note={"base_url": self.base_url}))
        return self

    # -- time / budget guards (mirror session.py) --
    def _elapsed(self):
        return self.clock() - self._t0 if self._t0 is not None else 0.0

    def _check_wall(self, op):
        if self._elapsed() > self.wall_s:
            self._log(interaction_record(self._next(), op, None, None, self.budget, note="wall_timeout"))
            raise WebWallTimeout(f"web wall budget {self.wall_s}s exceeded at {op}")

    def _account_recv(self, op, data):
        if self.budget.would_exceed(len(data)):
            self._spill_and_log(op, "recv", data, note="output_cap")
            self.budget.add(len(data))
            raise WebOutputCap(f"web output cap {self.budget.cap}B exceeded at {op}")
        self.budget.add(len(data))
        self._spill_and_log(op, "recv", data)

    # -- requests --
    def request(self, method, path, **kw):
        """Issue one HTTP request relative to base_url (or an absolute http://127.0.0.1... url).

        Returns the requests.Response. The request line/body and the response status/body are logged
        (byte-safe, capped); the response body counts against the output budget.
        """
        self._require_open()
        self._check_wall(method.lower())
        kw.setdefault("timeout", min(self.timeout, max(0.1, self.wall_s - self._elapsed())))
        kw.setdefault("allow_redirects", True)
        url = path if path.startswith("http://") or path.startswith("https://") else self.base_url + path
        # log the request (send direction): method+url + a preview of any body we are sending
        body = kw.get("data")
        if isinstance(body, (bytes, bytearray)):
            send_prev = bytes(body)
        elif body is not None:
            send_prev = repr(body).encode("utf-8", "replace")
        else:
            send_prev = (method + " " + url).encode("utf-8", "replace")
        self._spill_and_log(method.lower(), "send", send_prev,
                            note={"method": method.upper(), "url": url})
        resp = self._sess.request(method, url, **kw)
        raw = resp.content if resp.content is not None else b""
        self._spill_and_log(method.lower(), "recv", raw,
                            note={"status": resp.status_code, "url": resp.url,
                                  "content_type": resp.headers.get("Content-Type", "")})
        self._account_recv(method.lower(), raw)
        return resp

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    @property
    def cookies(self):
        return self._sess.cookies if self._sess is not None else None

    # -- close --
    def close(self):
        if self.closed:
            return
        self.closed = True
        if self._sess is not None:
            try:
                self._sess.close()
            except Exception:
                pass
        self._log(interaction_record(self._next(), "close", None, None, self.budget,
                                     note={"elapsed_s": round(self._elapsed(), 3),
                                           "output_used": self.budget.used}))
        try:
            self._tf.close()
        except Exception:
            pass

    # -- internals (mirror session.py) --
    def _require_open(self):
        if self.closed:
            raise SessionError("web client is closed")
        if self._sess is None:
            self.open()                      # auto-open on first request (idempotent)

    def _next(self):
        self._seq += 1
        return self._seq

    def _log(self, rec):
        import json
        self._tf.write(json.dumps(rec, sort_keys=True) + "\n")
        self._tf.flush()

    def _spill_and_log(self, op, direction, data, note=None):
        spill_ref = None
        if len(data) > INLINE_PREVIEW:
            self._spill += 1
            spill_ref = f"spill_{self._spill:04d}.bin"
            (self.log_dir / spill_ref).write_bytes(bytes(data))
        self._log(interaction_record(self._next(), op, direction, data, self.budget,
                                     spill_ref=spill_ref, note=note))
