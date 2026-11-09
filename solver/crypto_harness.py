"""Crypto solving harness — the entry point a reasoner (scripted now, LLM in
Phase 4) uses to drive a challenge.

Every solve script runs INSIDE the container (untrusted profile, --network none)
via tools.run_tool. The harness never executes solver code on the host, and it
never reads the scorer keys — only the challenge files are mounted (read-only)
into the container at /input. Outputs land in the per-run work dir.

Logs under store/runs/<run_id>/ reuse the Phase 0 convention:
  events.jsonl       append-only event log (via ExperimentLog)
  commands.jsonl     one record per actual container execution (+ dedup cache)
  experiments.jsonl  richer per-experiment record (stdout_ref, profile, status)
  candidates.jsonl   reported candidate flags + evidence refs
  state.json         resume/inspect snapshot (budget, hypotheses, candidates)
"""
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from solver.experiment_log import ExperimentLog, compute_dedup_key
from tools import sandbox
from tools.run_tool import run_tool

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CRYPTO_IMAGE = "ctfagent-crypto:0.1"
CONTAINER_INPUT = "/input"

# The one tool the crypto reasoner may run: arbitrary python, untrusted, so it is
# pinned to the container backend. run_tool refuses it on any weaker profile.
CRYPTO_ALLOWLIST = {
    "pycode": {"bin": "python3", "version_cmd": None, "smoke_cmd": None,
               "deterministic": True, "trust": "untrusted", "categories": ["crypto"],
               "sandbox_profile": "container"},
}

DEFAULT_BUDGET = {"time_s": 300, "max_attempts": 25}


@dataclass
class ExperimentOutcome:
    exp_id: str
    execution_status: str          # ok | error | timeout | aborted
    stdout: str
    stdout_ref: str
    sandbox_profile: str
    network_guaranteed: bool
    dedup_key: str
    cached: bool
    created_files: list = field(default_factory=list)


class CryptoHarness:
    def __init__(self, run_id, challenge_dir, store_root=None, budget=None,
                 image=CRYPTO_IMAGE, clock=None):
        self.run_id = run_id
        self.challenge_dir = Path(challenge_dir).resolve()
        self.challenge = json.loads((self.challenge_dir / "challenge.json").read_text())
        self.challenge_id = self.challenge["id"]
        root = Path(store_root) if store_root else PROJECT_ROOT / "store" / "runs"
        self.run_dir = (root / run_id).resolve()
        self.work_dir = self.run_dir / "work"
        self.artifacts_dir = self.run_dir / "artifacts"
        for d in (self.run_dir, self.work_dir, self.artifacts_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.clock = clock or time.monotonic
        self.image = image
        # When True, all experiments in this run share ONE /work (so unpacked sources, a
        # built harness, angr scripts survive between experiments) instead of a fresh
        # per-experiment jail. Opt-in (default off) so every existing lane/test is
        # unchanged; set per-route. Blindness is unaffected: /work is the agent's own
        # scratch -- it never holds the flag or vault, which stay unmounted + chmod-0.
        self.persist_work = False
        # container cfg: default sandbox.json params, image swapped for the crypto image
        base_cfg = sandbox.load_sandbox_config()
        base_cfg["container"] = dict(base_cfg["container"], image=image)
        self.sandbox_config = base_cfg
        # The tool allowlist used for container runs. A subclass (e.g. the mlsec
        # harness) may swap this for one whose categories match its own lane.
        self.allowlist = CRYPTO_ALLOWLIST

        self.budget = dict(DEFAULT_BUDGET if budget is None else budget)
        self.budget_spent = {"time_s": 0.0, "attempts": 0}
        self.hypotheses = []
        self.candidates = []
        self.experiments = {}          # exp_id -> record
        self._ref_by_key = {}          # dedup_key -> (exp_id, stdout_ref, status, profile)
        self.elog = ExperimentLog(self.run_dir)
        self._t0 = self.clock()
        self.elog.append_event("harness_started", challenge_id=self.challenge_id, image=image)
        self._save()

    # ---- budget --------------------------------------------------------------

    def check_budget(self):
        spent_time = self.budget_spent["time_s"] + (self.clock() - self._t0)
        if spent_time >= self.budget["time_s"]:
            return False, "time_s"
        if self.budget_spent["attempts"] >= self.budget["max_attempts"]:
            return False, "max_attempts"
        return True, None

    # ---- reasoner-facing API -------------------------------------------------

    def record_hypothesis(self, statement, rationale="", priority_band="mid"):
        hid = f"{self.challenge_id}-H{len(self.hypotheses)}"
        h = {"id": hid, "statement": statement, "rationale": rationale,
             "priority_band": priority_band, "status": "proposed"}
        self.hypotheses.append(h)
        self.elog.append_event("hypothesis", hypothesis_id=hid, statement=statement)
        self._save()
        return hid

    def run_experiment(self, spec):
        """Run a solve step in the container. spec: {name, code, timeout?, nondeterministic?}.

        `code` is python source executed as /work/<name>.py with the challenge
        files mounted read-only at /input. Returns an ExperimentOutcome.
        """
        name = spec["name"]
        exp_id = f"{self.challenge_id}-{name}"
        ok, reason = self.check_budget()
        if not ok:
            self.elog.append_event("experiment_blocked", experiment_id=exp_id, blocked_by=reason)
            outcome = ExperimentOutcome(exp_id, "aborted", "", "", "none", False, "", False)
            self.experiments[exp_id] = self._exp_record(outcome, blocked_by=reason)
            self._save()
            return outcome

        # Per-experiment jail by default; one shared jail (persisted /work) when opted in.
        exp_work = (self.work_dir / "_shared") if self.persist_work else (self.work_dir / name)
        exp_work.mkdir(parents=True, exist_ok=True)
        script = exp_work / f"{name}.py"   # name is unique per call, so scripts never collide
        script.write_text(spec["code"])
        timeout = spec.get("timeout", 30)
        nondeterministic = bool(spec.get("nondeterministic", False))

        # Run isolated (-I): the script's /work directory is NOT put on sys.path, so a
        # planted or oddly-named script/input (inspect.py, os.py) can't shadow stdlib.
        container_argv = ["-I", f"{name}.py"]
        # dedup key: image + argv + hashes of script and all mounted input files
        input_files = [str(script)] + [str(self.challenge_dir / f) for f in self.challenge.get("files", [])]
        dedup_key = compute_dedup_key(
            "pycode", self.image, container_argv, input_files, {}, timeout, "/work")

        cached = (not nondeterministic) and dedup_key in self._ref_by_key
        if cached:
            prev = self._ref_by_key[dedup_key]
            stdout = self._read_ref(prev["stdout_ref"])
            self.elog.append_event("experiment_dedup_hit", experiment_id=exp_id, dedup_key=dedup_key)
            outcome = ExperimentOutcome(exp_id, prev["status"], stdout, prev["stdout_ref"],
                                        prev["profile"], True, dedup_key, True)
            self.experiments[exp_id] = self._exp_record(outcome)
            self._save()
            return outcome

        run_spec = {
            "tool_id": "pycode",
            "argv": ["pycode", *container_argv],
            "execution_id": exp_id,
            "timeout": timeout,
            "nondeterministic": nondeterministic,
            "input_dir": str(self.challenge_dir),
        }
        result = run_tool(run_spec, jail_root=str(exp_work), artifacts_dir=str(self.artifacts_dir),
                          allowlist=self.allowlist, sandbox_config=self.sandbox_config)
        self.budget_spent["attempts"] += 1
        self.budget_spent["time_s"] += result.duration
        stdout = self._read_ref(result.stdout_ref)

        # commands.jsonl record (actual execution) + event
        self.elog.command_seq += 1
        cmd = {"seq": self.elog.command_seq, "experiment_id": exp_id, "tool": "pycode",
               "version": self.image, "argv": container_argv, "input_files": input_files,
               "env": {}, "cwd": "/work", "timeout": timeout, "nondeterministic": nondeterministic,
               "dedup_key": dedup_key, "execution_status": result.execution_status,
               "observation": stdout[:4096]}
        with open(self.run_dir / "commands.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(cmd, sort_keys=True) + "\n")
        self.elog.append_event("experiment_executed", experiment_id=exp_id, dedup_key=dedup_key,
                               execution_status=result.execution_status,
                               sandbox_profile=result.sandbox_profile,
                               network_guaranteed=result.network_guaranteed)

        if result.execution_status == "ok" and not nondeterministic:
            self._ref_by_key[dedup_key] = {"exp_id": exp_id, "stdout_ref": result.stdout_ref,
                                           "status": result.execution_status,
                                           "profile": result.sandbox_profile}
        outcome = ExperimentOutcome(
            exp_id, result.execution_status, stdout, result.stdout_ref, result.sandbox_profile,
            result.network_guaranteed, dedup_key, False, result.created_files)
        self.experiments[exp_id] = self._exp_record(outcome)
        self._save()
        return outcome

    def report_candidate(self, value, evidence_refs):
        """Report a candidate flag. evidence_refs: list of exp_ids that produced it."""
        cand = {"value": value, "evidence_refs": list(evidence_refs), "status": "UNVERIFIED"}
        self.candidates.append(cand)
        with open(self.run_dir / "candidates.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(cand, sort_keys=True) + "\n")
        self.elog.append_event("candidate_reported", value=value, evidence_refs=list(evidence_refs))
        self._save()
        return cand

    def get_state(self):
        return json.loads((self.run_dir / "state.json").read_text())

    # ---- internals -----------------------------------------------------------

    def _exp_record(self, o: ExperimentOutcome, blocked_by=None):
        rec = {"exp_id": o.exp_id, "execution_status": o.execution_status,
               "stdout_ref": o.stdout_ref, "sandbox_profile": o.sandbox_profile,
               "network_guaranteed": o.network_guaranteed, "dedup_key": o.dedup_key,
               "cached": o.cached, "created_files": o.created_files}
        if blocked_by:
            rec["blocked_by"] = blocked_by
        with open(self.run_dir / "experiments.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def _read_ref(self, ref):
        if not ref:
            return ""
        p = self.artifacts_dir / Path(ref).name
        try:
            return p.read_text(errors="replace")
        except OSError:
            return ""

    def _save(self):
        spent = dict(self.budget_spent)
        spent["time_s"] = self.budget_spent["time_s"]
        state = {
            "run_id": self.run_id, "challenge_id": self.challenge_id, "image": self.image,
            "budget": self.budget, "budget_spent": spent,
            "hypotheses": self.hypotheses, "candidates": self.candidates,
            "experiments": self.experiments,
        }
        tmp = self.run_dir / "state.json.tmp"
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
        os.replace(tmp, self.run_dir / "state.json")
