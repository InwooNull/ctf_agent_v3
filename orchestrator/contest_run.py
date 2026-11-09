"""Phase CM5: the whole contest machine wired together, end to end.

Per challenge, driven by the CM3 RotationRunner:
    skill_pack inject  (CM4, no raw solving)
    scoped egress      (CM2 EgressBroker: reach ONLY the declared target)
    harness solve       -> the category solver reaches the target THROUGH the broker
    evidence capture    (CM4: the flag must come from a real target/exec output)
    checkpoint + events (CM3: every challenge's progress preserved, resumable)
    writeup_log         (CM4: real model + prompt + output recorded for disclosure)
    candidate display   (CM4: shown for MANUAL submit; no auto-submit, ever)

The blind bench harnesses (tools/web_service, tools/pwn_service) are `--network none`
by design and hold the flag locally — they are NOT reused for contest. Contest solving
reaches an EXTERNAL target, so it goes through the scoped EgressBroker instead. The
container-solver variant resolves a hostname target onto the broker with --add-host
(see tools.contest_net.container_add_host); the integrated path here resolves it in
the broker directly.

Stdlib only; reuses governance modules, edits none.
"""
import re
import socket
from pathlib import Path

from orchestrator import mode as mode_mod
from orchestrator import rotation as rot
from orchestrator.contest_log import (
    WriteupLog, CandidateBoard, ContestExperience, skill_prompt, contest_run_dir,
)
from orchestrator.classifier import classify as classify_category
from orchestrator import skill_pack
from tools import contest_net as cn
from orchestrator import contest_files
from orchestrator import contest_solvers
from solver import contest_evidence as ce
from schemas.records import Candidate

DEFAULT_PATHS = ("/flag", "/", "/index.html")
_FLAGISH = re.compile(r"[A-Za-z0-9_]+\{[^}\n]{1,200}\}")


class ChallengeCtx:
    """Everything one challenge's solver needs, including a broker-scoped fetch."""

    def __init__(self, cid, target, category, broker, verifier, flag_format, prompt):
        self.cid = cid
        self.target = target          # (host, port) — the ONLY reachable endpoint
        self.category = category
        self.broker = broker
        self.verifier = verifier
        self.flag_format = flag_format
        self.prompt = prompt          # skill_pack-injected prompt (what the agent sees)

    def fetch(self, request_bytes, read_limit=65536, timeout=5):
        """Send bytes to the target THROUGH the scoped broker; return (data, status).

        status is 'OK' on a real tunnel, else the broker's refusal ('DENIED' etc.).
        This is the only egress path the solver has — non-target hosts are unreachable."""
        host, port = self.target
        try:
            s = socket.create_connection(self.broker.address, timeout=timeout)
        except OSError as e:
            return b"", f"broker_unreachable:{e}"
        try:
            s.sendall(f"{host} {port}\n".encode())
            s.settimeout(timeout)
            head = b""
            while b"\n" not in head and len(head) < 64:
                c = s.recv(16)
                if not c:
                    break
                head += c
            status = head.split(b"\n", 1)[0].decode("ascii", "replace")
            if status != "OK":
                return b"", status or "no_status"
            s.sendall(request_bytes)
            data = b""
            while len(data) < read_limit:
                c = s.recv(4096)
                if not c:
                    break
                data += c
            return data, "OK"
        except OSError as e:
            return b"", f"io_error:{e}"
        finally:
            try:
                s.close()
            except OSError:
                pass


def default_web_solver(ctx, round_idx, info):
    """A minimal, non-weaponizing web technique: GET a few candidate paths THROUGH the
    broker and look for a flag in the real server response. Each round tries one path.

    Returns the RotationRunner solver contract. A found flag is grounded in the captured
    server response (CM4 evidence), so only a genuine target hit becomes a solve."""
    path = DEFAULT_PATHS[round_idx] if round_idx < len(DEFAULT_PATHS) else None
    if path is None:
        return {"info_gain": 0, "log": "exhausted default paths"}
    host = ctx.target[0]
    req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    data, status = ctx.fetch(req)
    text = data.decode("utf-8", "replace")
    log = f"GET {path} -> status={status} bytes={len(data)}"
    if status != "OK":
        return {"info_gain": 0, "log": log}
    ev = ctx.verifier.capture(ce.SRC_TARGET, text, label=f"GET {path}")
    m = _FLAGISH.search(text)
    if m and ce.matches_format(m.group(0), ctx.flag_format):
        flag = m.group(0)
        return {"info_gain": 1, "log": log + f" FLAG={flag}",
                "candidate": Candidate(value=flag, confidence=0.9,
                                       evidence_refs=[ev], status="VERIFIED")}
    return {"info_gain": 1 if data else 0, "log": log + " (no flag in response)"}


# CM5 web + CM9 pwn(net). rev/crypto are file-artifact routes, dispatched in _solve by
# category (they drive their own container harnesses), not via this net registry.
DEFAULT_REGISTRY = {"web": default_web_solver,
                    "pwn": contest_solvers.contest_pwn_solver}

# category -> file-artifact solver (CM9). Falls back to the CM6/7 analyzer (file_solver).
FILE_SOLVERS = {"rev": contest_solvers.contest_rev_solver,
                "crypto": contest_solvers.contest_crypto_solver,
                "pwn": contest_solvers.contest_local_pwn_solver}


class ContestPipeline:
    """Integrated contest run: rotation + egress + evidence + writeup + candidates."""

    def __init__(self, items, store_root, run_id, *, solver_registry=None,
                 model="unspecified", global_caps=None, challenge_caps=None,
                 slice_rounds=2, no_progress_k=3, record_experience=False):
        self.items = [dict(it) for it in items]
        self.run_dir = contest_run_dir(run_id, store_root)
        self.writeup = WriteupLog(self.run_dir)
        self.board = CandidateBoard(self.run_dir)
        self.experience = ContestExperience(store_root) if record_experience else None
        self.registry = dict(solver_registry or DEFAULT_REGISTRY)
        self.model = model
        self.ctx = {}
        self._brokers = []
        for it in self.items:
            cid = it["id"]
            cat = it.get("category") or "web"
            fmt = it.get("flag_format") or "flag{...}"
            verifier = ce.ContestVerifier(self.run_dir / cid, flag_format=fmt)
            if it.get("solve_kind") == "file":
                # CM6: local artifact — no network/broker; sandboxed analysis evidence.
                base_prompt = it.get("prompt") or f"Analyze the {cat} artifact for {cid}"
                injected = skill_prompt(cat, base_prompt)
                ctx = contest_files.FileChallengeCtx(
                    cid, cat, verifier, fmt, it["file_dir"], it.get("files") or [],
                    injected, self.run_dir / cid / "work", it.get("family"), it.get("tool"))
                ctx.skill_injected = (injected != base_prompt)
                self.ctx[cid] = ctx
                continue
            # network challenge (CM5): scoped egress broker to the declared target
            target_list = cn.parse_target(it.get("target") or it.get("target_decl") or "")
            if not target_list:
                raise ValueError(f"challenge {cid}: no parseable target to scope egress")
            policy = cn.EgressPolicy(target_list)          # default-deny allowlist (CM2)
            broker = cn.EgressBroker(policy).start()
            self._brokers.append(broker)
            base_prompt = it.get("prompt") or f"Solve the {cat} challenge {cid} at {it.get('target')}"
            injected = skill_prompt(cat, base_prompt)       # skill_pack injection (CM4)
            ctx = ChallengeCtx(cid, target_list[0], cat, broker, verifier, fmt, injected)
            ctx.kind = "net"
            ctx.skill_injected = (injected != base_prompt)
            self.ctx[cid] = ctx
        self.runner = rot.RotationRunner(
            self.items, self._solve, self.run_dir, submit=self._submit,
            mode=mode_mod.CONTEST, global_caps=global_caps, challenge_caps=challenge_caps,
            slice_rounds=slice_rounds, no_progress_k=no_progress_k)

    def _solve(self, cid, round_idx, info):
        ctx = self.ctx[cid]
        if getattr(ctx, "kind", "net") == "file":
            # CM9: rev/crypto/pwn file artifacts drive their own category harness; every
            # other family keeps the CM6/7 sandboxed analyzer (file_solver).
            file_solver = FILE_SOLVERS.get(ctx.category, contest_files.file_solver)
            r = file_solver(ctx, round_idx, info) or {}
        else:
            solver = self.registry.get(ctx.category, default_web_solver)
            r = solver(ctx, round_idx, info) or {}
        # writeup runtime hook: real model + the (injected) prompt + the output (CM4)
        self.writeup.record(cid, model=self.model, prompt=ctx.prompt,
                            output=r.get("log", ""), step=f"round{round_idx}",
                            skill_injected=ctx.skill_injected, category=ctx.category)
        return r

    def _submit(self, cid, candidate):
        """Assess locally (NO server contact) and surface the candidate to the user."""
        ctx = self.ctx[cid]
        refs = getattr(candidate, "evidence_refs", None) or None
        res = ctx.verifier.assess(getattr(candidate, "value", candidate), evidence_refs=refs)
        self.board.present(cid, res["flag"], verdict=res["verdict"],
                           confidence=res["confidence"], evidence_refs=res["evidence_refs"])
        solved = res["verdict"] == ce.VERIFIED
        if solved and self.experience is not None:
            self.experience.add({"cid": cid, "category": ctx.category,
                                 "technique": f"{ctx.category}:default", "verified": True})
        return solved

    def run(self, max_slices=None):
        try:
            summ = self.runner.run(max_slices=max_slices)
        finally:
            for b in self._brokers:
                b.stop()
        summ["candidates"] = self.board.all()
        summ["verified_candidates"] = self.board.verified()
        summ["writeup_entries"] = len(self.writeup.entries())
        summ["run_dir"] = str(self.run_dir)
        return summ


# ---- input -> challenge items ---------------------------------------------------

def items_from_plan(plan, env=None):
    """Build the challenge set for a solve plan. CM5 implements the 'url' (single live
    target) path fully; ctfd/dir/file reuse the connector/arena collectors."""
    kind = plan["kind"]
    if kind == "url":
        return [{"id": "t1", "target": plan["input"], "category": "web",
                 "flag_format": "flag{...}", "score": 100, "difficulty": "med",
                 "est_cost": 1.0}]
    if kind == "ctfd":
        from connector.ctfd_client import CTFdClient
        from connector import fetch as cfetch
        client = CTFdClient.from_env(env) if env else CTFdClient.from_env()
        results, _ = cfetch.fetch_all(client)
        items = []
        for r in results:
            cid = r["cid"]
            chal = {}
            try:
                import json
                chal = json.loads((cfetch.ARENA / cid / "challenge.json").read_text())
            except OSError:
                pass
            items.append({"id": cid, "target": chal.get("description", ""),
                          "category": classify_category(chal) if chal else "web",
                          "flag_format": chal.get("flag_format", "flag{...}"),
                          "score": r.get("value") or 100, "difficulty": "med", "est_cost": 1.0})
        return items
    if kind in ("dir", "file"):
        # CM6: local file/folder artifact(s) -> sandboxed file-analysis challenges
        return contest_files.file_items_from_input(plan["input"])
    raise NotImplementedError(f"solve --run for kind={kind!r} is not wired")


def run_plan(plan, env=None, *, store_root=None, run_id=None, solver_registry=None,
             model="unspecified", global_caps=None, challenge_caps=None):
    """Execute a contest plan end to end. Returns a process rc (0 ran, 2 error)."""
    import time
    from pathlib import Path as _P
    if plan["mode"] != mode_mod.CONTEST:
        print(f"[solve] --run in {plan['mode']} mode is not supported here "
              f"(bench stays blind, --network none).")
        return 2
    try:
        items = items_from_plan(plan, env=env)
    except (NotImplementedError, Exception) as e:
        print(f"[solve] --run ERROR building challenges: {e}")
        return 2
    run_id = run_id or f"run_{int(time.time())}"
    store_root = store_root or (_P(__file__).resolve().parents[1] / "store")
    pipe = ContestPipeline(items, store_root, run_id, solver_registry=solver_registry,
                           model=model, global_caps=global_caps, challenge_caps=challenge_caps)
    summ = pipe.run()
    print(f"[solve] run {run_id}: "
          f"solved={summ['solved']}  status={summ['status']}")
    for c in summ["candidates"]:
        tag = "SOLVE" if c["verdict"] == ce.VERIFIED else "candidate"
        print(f"  [{tag}] {c['cid']}: {c['flag']}  conf={c['confidence']} "
              f"evidence={c['evidence_refs']}  -> submit MANUALLY (no auto-submit)")
    print(f"[solve] writeup_log + evidence under: {summ['run_dir']}")
    return 0
