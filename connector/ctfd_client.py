"""ACDC 2026 platform client (stdlib urllib only).

The qualifier runs a custom Next.js frontend over a CTFd-derived backend. Auth is
NOT token-based (the proxy rejects `Authorization: Token ...`); it is a **session
cookie** obtained by posting credentials to /api/v2/auth/login. Everything else is
under /api/v2:
  POST /api/v2/auth/login            {name, password}      -> sets `session` cookie
  GET  /api/v2/auth/check/cookie                           -> {authenticated, user}
  GET  /api/v2/challenges                                  -> list
  GET  /api/v2/challenges/<id>                             -> detail (files, hints, ...)
  GET  <file url '/files/..?token=..'>                     -> raw bytes
  POST /api/v2/challenges/attempt    {challenge_id, submission} -> {status, message}

KOTH ("livefire") challenges use a separate /api/v2/livefire/* API and real-time
scoring, not flag submission; this client handles the flag-based challenges.

Credentials come from config/acdc.env (git-ignored, chmod 600) via load_env().
"""
import json
import os
import re
import http.cookiejar
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from connector.retry import (
    NETWORK_RETRIES, is_transient_network_error, network_backoff,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV = PROJECT_ROOT / "config" / "acdc.env"
LOGIN_PATH = "/api/v2/auth/login"

# CTFd/ACDC category label -> our solver-pipeline bucket. The AI-security tracks
# have no classic analogue; they route to "ai" (handled analytically, not by the
# docker crypto/pwn/web/rev/misc harnesses). KOTH is live and separate.
CATEGORY_MAP = {
    "crypto": "crypto", "cryptography": "crypto",
    "pwn": "pwn", "pwnable": "pwn", "binary exploitation": "pwn",
    "web": "web", "web exploitation": "web",
    "rev": "rev", "reversing": "rev", "reverse engineering": "rev",
    "forensics": "misc", "misc": "misc", "stego": "misc", "osint": "misc",
    "security for ai": "ai", "ai for security": "ai",
    "ai platform security": "ai",
    "koth": "koth",
}


def normalize_category(label):
    if not label:
        return "misc"
    return CATEGORY_MAP.get(label.strip().lower(), "ai")


def load_env(path=DEFAULT_ENV):
    env = {}
    p = Path(path)
    if not p.is_file():
        return env
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


class CTFdError(RuntimeError):
    pass


class RateLimited(CTFdError):
    pass


class AuthError(CTFdError):
    pass


class CTFdClient:
    def __init__(self, base_url, name=None, password=None, timeout=30,
                 user_agent="acdc-connector/0.2", sleep=time.sleep):
        if not base_url:
            raise CTFdError("base_url is required")
        self.base = base_url.rstrip("/")
        self.name = name
        self.password = password
        self.timeout = timeout
        self.user_agent = user_agent
        self._sleep = sleep
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj))
        self._authed = False

    @classmethod
    def from_env(cls, path=None, **kw):
        env = load_env(path or DEFAULT_ENV)
        url = env.get("ACDC_URL") or os.environ.get("ACDC_URL")
        name = env.get("ACDC_USERNAME") or os.environ.get("ACDC_USERNAME")
        pw = env.get("ACDC_PASSWORD") or os.environ.get("ACDC_PASSWORD")
        if not url or not name or not pw:
            raise CTFdError(f"ACDC_URL / ACDC_USERNAME / ACDC_PASSWORD missing in {path or DEFAULT_ENV}")
        return cls(url, name=name, password=pw, **kw)

    # ---- low-level HTTP -------------------------------------------------
    def _request(self, method, path, body=None, expect_json=True, _retry=0):
        url = path if path.startswith("http") else f"{self.base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json", "User-Agent": self.user_agent,
                   # main CTFd enforces same-origin on state-changing calls (403
                   # "request origin or CSRF token incorrect") — send Origin/Referer.
                   "Origin": self.base,
                   "Referer": f"{self.base}/challenges"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise RateLimited(f"429 rate limited on {method} {path}")
            detail = e.read().decode("utf-8", "replace")[:500]
            if e.code == 401 and self._authed and path != LOGIN_PATH and _retry == 0:
                # The session cookie was closed mid-run (c14 lesson). Open a fresh
                # session once and resume the same request — context preserved.
                self._authed = False
                self.cj.clear()
                self.login()
                return self._request(method, path, body, expect_json, _retry + 1)
            if e.code in (401, 403):
                raise AuthError(f"HTTP {e.code} on {method} {path}: {detail}")
            raise CTFdError(f"HTTP {e.code} on {method} {path}: {detail}")
        except urllib.error.URLError as e:
            # Only a *transient* blip (EAI_AGAIN / reset / timeout) is worth retrying;
            # a hard URLError (e.g. connection refused to a dead host) still raises.
            if is_transient_network_error(e) and _retry < NETWORK_RETRIES:
                self._sleep(network_backoff(_retry + 1))
                return self._request(method, path, body, expect_json, _retry + 1)
            raise CTFdError(f"network error on {method} {path}: {e}")
        if not expect_json:
            return raw
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise CTFdError(f"non-JSON from {method} {path}: {e}")
        if isinstance(parsed, dict) and parsed.get("success") is False:
            raise CTFdError(f"success=false on {method} {path}: {parsed}")
        return parsed

    # ---- auth -----------------------------------------------------------
    def login(self):
        resp = self._request("POST", "/api/v2/auth/login",
                             body={"name": self.name, "password": self.password})
        if not resp.get("success"):
            raise AuthError(f"login failed: {resp}")
        self._authed = True
        return resp.get("user", {})

    def _ensure_auth(self):
        if not self._authed:
            self.login()

    def whoami(self):
        self._ensure_auth()
        return self._request("GET", "/api/v2/auth/check/cookie").get("user", {})

    # ---- API surface ----------------------------------------------------
    def list_challenges(self):
        self._ensure_auth()
        return self._request("GET", "/api/v2/challenges").get("data", [])

    def get_challenge(self, challenge_id):
        self._ensure_auth()
        return self._request("GET", f"/api/v2/challenges/{challenge_id}").get("data", {})

    def download_file(self, file_url):
        self._ensure_auth()
        return self._request("GET", file_url, expect_json=False)

    def submit_flag(self, challenge_id, flag):
        """THE outward action. Returns (status, message).
        status in {correct, incorrect, already_solved, paused, ratelimited, ...}."""
        self._ensure_auth()
        body = {"challenge_id": int(challenge_id), "submission": flag}
        resp = self._request("POST", "/api/v2/challenges/attempt", body=body)
        data = resp.get("data", {}) if isinstance(resp, dict) else {}
        status = (data.get("status") or "").lower()
        if status == "ratelimited":
            raise RateLimited(f"submit ratelimited for challenge {challenge_id}")
        return status, data.get("message", "")


def flag_format_from_sample(flag_or_format):
    if not flag_or_format:
        return "see description"
    m = re.match(r"^([A-Za-z0-9_]+)\{.*\}$", flag_or_format.strip())
    return f"{m.group(1)}{{...}}" if m else flag_or_format.strip()
