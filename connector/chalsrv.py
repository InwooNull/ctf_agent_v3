"""Robust client for the ACDC per-challenge instance servers (stdlib only).

Hardens the weaknesses hit when driving the live AI-injection challenges:
  - flaky backends return status "system_error" with empty stages  -> auto-retry
  - short-window 429s (e.g. 5/60s)                                  -> honor retry_after
  - retry-on-timeout was creating DUPLICATE attempts                -> single in-flight:
        never re-POST an attempt; instead poll the attempt list and read the result
  - no record of what was tried                                    -> append-only JSONL log

Two challenge-server API shapes are covered:

  AttemptServer  (/v1 ...)   — Semantic Collision c11, Judgeception c13, Memory c14 (:8002)
     POST /v1/challenges/<cid>/attempts   {text}      -> attempt (runs normalizer/guard/executor/...)
     GET  /v1/challenges/<cid>/attempts               -> [ {attempt_id, status, solved}, ... ]
     GET  /v1/attempts/<attempt_id>                   -> full attempt

  DocServer      (/api ...)  — RAG Poisoner 12, Chain of Agents 15 (:8003)
     PUT  /api/challenges/<cid>/document  {title,content}
     POST /api/challenges/<cid>/evaluate  {}          -> evaluation (retrieval/task/tool stages)
     GET  /api/challenges/<cid>/attempts[/<id>]

Auth is the CTFd token as a Bearer credential (NOT the main platform; those servers
reject it, these require it). Token from env ACDC_TOKEN or config/acdc.env.
"""
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from connector.ctfd_client import load_env, DEFAULT_ENV
from connector.retry import Backoff, is_transient_network_error

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOGDIR = PROJECT_ROOT / "store" / "live" / "attempts"


def _token(path=None):
    env = load_env(path or DEFAULT_ENV)
    import os
    return env.get("ACDC_TOKEN") or os.environ.get("ACDC_TOKEN")


class _Base:
    def __init__(self, base_url, token=None, log_name=None, verbose=True,
                 sleep=time.sleep):
        self.base = base_url.rstrip("/")
        self.token = token or _token()
        self.verbose = verbose
        self._sleep = sleep
        self.log_path = (LOGDIR / f"{log_name}.jsonl") if log_name else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _log(self, kind, obj):
        if not self.log_path:
            return
        rec = {"ts": time.time(), "kind": kind, "obj": obj}
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _say(self, *a):
        if self.verbose:
            print(*a, flush=True)

    def _http(self, method, path, body=None, to=300):
        url = path if path.startswith("http") else self.base + path
        data = json.dumps(body).encode() if body is not None else None
        h = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=to) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:
            return "ERR", str(e)[:200]


class AttemptServer(_Base):
    """/v1 attempt-style challenges (guard/executor pipeline)."""

    def list_attempts(self, cid):
        s, b = self._http("GET", f"/v1/challenges/{cid}/attempts", to=40)
        try:
            return json.loads(b)
        except Exception:
            return []

    def get_attempt(self, attempt_id, to=60):
        s, b = self._http("GET", f"/v1/attempts/{attempt_id}", to=to)
        try:
            return json.loads(b)
        except Exception:
            return {"status": "parse_error", "_raw": b[:300]}

    def wait_idle(self, cid, max_wait=320):
        """Block until no attempt for this challenge is 'running'."""
        waited = 0
        while waited < max_wait:
            for a in self.list_attempts(cid):
                if a.get("status") == "running":
                    break
            else:
                return True
            self._sleep(8)
            waited += 8
        return False

    def await_result(self, cid, attempt_id, to=320):
        """Poll until the attempt leaves 'running'; return full attempt."""
        waited = 0
        while waited < to:
            o = self.get_attempt(attempt_id)
            if o.get("status") != "running":
                return o
            self._sleep(6)
            waited += 6
        return self.get_attempt(attempt_id)

    def submit(self, cid, text, retries=5, settle=18, retry_on_block=False):
        """Submit ONE request text and return the completed attempt dict.

        Single in-flight: wait for idle, POST once, then READ the result by id
        (never re-POST, so no duplicate attempts). Retries only the *model-side*
        system_error and the 429 (which create no attempt). Logs every outcome.
        Consecutive 429s escalate the backoff so we stop thrashing the rate window.
        """
        self._log("submit_text", {"cid": cid, "text": text})
        backoff = Backoff(settle=settle, sleep=self._sleep)
        for i in range(retries):
            # SINGLE IN-FLIGHT: wait for no running attempt, POST exactly once, then
            # READ the outcome by id. We never re-POST an attempt — that is what
            # created duplicate attempts live. Only 429 / system_error (which create
            # NO attempt) loop back to a fresh POST.
            self.wait_idle(cid)
            backoff.settle_wait()  # clear short rate window
            s, b = self._http("POST", f"/v1/challenges/{cid}/attempts", {"text": text})
            if s == 429:
                try:
                    ra = json.loads(b).get("error", {}).get("retry_after_seconds")
                except Exception:
                    ra = None
                waited = backoff.on_rate_limited(ra)
                self._say(f"  [{cid}] 429 x{backoff.consecutive_429}, wait {waited}s (try {i+1}/{retries})")
                continue
            if s == "ERR" and is_transient_network_error(b):
                # transient network/DNS blip: no attempt was created, retry the POST
                self._say(f"  [{cid}] network blip ({b[:60]}), retry (try {i+1}/{retries})")
                backoff.on_system_error()
                continue
            backoff.on_success()
            try:
                o = json.loads(b)
            except Exception:
                self._say(f"  [{cid}] parsefail {s}: {b[:120]}")
                self._sleep(12)
                continue
            if o.get("status") == "running":
                o = self.await_result(cid, o.get("attempt_id"))
            if o.get("status") == "system_error":
                self._say(f"  [{cid}] system_error, retry (try {i+1}/{retries})")
                backoff.on_system_error()  # ride out provider_failed/system_error windows
                continue
            if retry_on_block:
                verdicts = [st.get("data", {}).get("verdict")
                            for st in o.get("stages", []) if st.get("stage") == "guard"]
                if "BLOCK" in verdicts and not o.get("tool_calls"):
                    self._say(f"  [{cid}] guard BLOCK (stochastic), retry (try {i+1}/{retries})")
                    self._log("attempt_result", _slim(o))
                    self._sleep(6)
                    continue
            self._log("attempt_result", _slim(o))
            return o
        return {"status": "exhausted"}


class DocServer(_Base):
    """/api document-replacement challenges (RAG / multi-stage)."""

    def put_document(self, cid, title, content):
        s, b = self._http("PUT", f"/api/challenges/{cid}/document",
                          {"title": title, "content": content})
        self._log("put_document", {"cid": cid, "title": title, "len": len(content)})
        return s, b

    def evaluate(self, cid, retries=5, settle=6):
        self._log("evaluate", {"cid": cid})
        for i in range(retries):
            s, b = self._http("POST", f"/api/challenges/{cid}/evaluate", {})
            if s == 429:
                try:
                    ra = json.loads(b).get("retry_after", json.loads(b).get("error", {}).get("retry_after_seconds", 8))
                except Exception:
                    ra = 8
                try:
                    ra = int(ra)
                except Exception:
                    ra = 8
                self._say(f"  [{cid}] 429, wait {ra+2}s")
                self._sleep(ra + 2)
                continue
            try:
                o = json.loads(b)
            except Exception:
                self._sleep(settle)
                continue
            if o.get("status") in ("system_error", "error") and not o.get("stages"):
                self._sleep(12)
                continue
            self._log("eval_result", _slim(o))
            return o
        return {"status": "exhausted"}


def _slim(o):
    """Compact view of an attempt/eval for logging (no giant blobs)."""
    keep = {k: o.get(k) for k in ("attempt_id", "id", "status", "solved", "success", "flag")}
    if isinstance(o.get("stages"), list):
        keep["stages"] = [{"stage": s.get("stage"),
                           "verdict": s.get("data", {}).get("verdict"),
                           "data": s.get("data")} for s in o["stages"]]
    elif isinstance(o.get("stages"), dict):
        keep["stages"] = o["stages"]
    keep["tool_calls"] = o.get("tool_calls")
    return keep


# convenience constructors for the known hosts
def semantic():   return AttemptServer("https://befd24.acdc2026.challenge-server.com:8002", log_name="c11_semantic")
def judge():      return AttemptServer("https://befd24.acdc2026.challenge-server.com:8002", log_name="c13_judge")
def memory():     return AttemptServer("https://befd24.acdc2026.challenge-server.com:8002", log_name="c14_memory")
def rag():        return DocServer("https://b5c26d.acdc2026.challenge-server.com:8003", log_name="rag12")
def chain():      return DocServer("https://b5c26d.acdc2026.challenge-server.com:8003", log_name="chain15")
