"""Harness that runs each experiment on the Phase 19 web-service 2-uid boundary.

Same reasoner-facing API as CryptoHarness (run_experiment / report_candidate / get_state /
check_budget; experiments/candidates/state logs) so the C0 CLI drives it unchanged, but every
experiment is one 2-uid --network none container (tools.web_service.run): the agent code runs as the
agent uid with the PUBLIC app source at /input/tree, and the flag-bearing web app reachable only over
the loopback HTTP tube (solver.web_client.WebClient). The agent cannot read the service-owned data dir
that holds the staged secret.

The flag is staged by the runner at store/<set>/_boot/<run_id>/flag (readable by the harness process,
never mounted to the agent); blindness for it rests on the in-container uid boundary + the CLI-only
transcript audit + the atime trap (a same-uid subagent cannot be walled off by file mode alone).
"""
import json
from pathlib import Path

from solver.crypto_harness import CryptoHarness, ExperimentOutcome
from tools import web_service

# Default image. Resolved at call time (not bound as a default arg) so a runner/CLI can switch it.
WEB_IMAGE = "ctfagent-web:0.1"
# The finals image ctfagent-web:0.3 (Phase 43: +ffuf, +playwright/chromium best-effort;
# sqlmap already in 0.1/0.2) is selected explicitly via image= by a C1 web run, exactly as
# misc kept 0.1 default and passed 0.3 to its C1 runner, and rev kept 0.1 vs 0.2. The 0.3
# tool knowledge lives in the skills/web router pack.
WEB_IMAGE_FINALS = "ctfagent-web:0.3"
# Attack tools reachable from an experiment (subprocess) against the loopback target.
# Present in ALL web images (sqlmap) vs only in WEB_IMAGE_FINALS (ffuf, playwright+chromium).
WEB_TOOLS = ("sqlmap", "requests", "httpx", "beautifulsoup4",
             "web_client.WebClient (cookie-persistent HTTP client)", "python3 (urllib, re, json)")
# playwright+chromium is BEST-EFFORT in 0.3 (heavy); a run must check
# /opt/ctfagent/playwright_status.txt before relying on the headless lane.
WEB_FINALS_TOOLS = ("ffuf", "playwright (headless chromium; best-effort, verify presence)")


class WebServiceHarness(CryptoHarness):
    def __init__(self, run_id, challenge_dir, store_root=None, budget=None, image=None, clock=None,
                 port=web_service.DEFAULT_PORT):
        image = image or WEB_IMAGE
        super().__init__(run_id, challenge_dir, store_root=store_root, budget=budget, image=image, clock=clock)
        # The public instance ships tree/<app_rel> (the server source the agent may read) + challenge.json.
        # No host-side deploy step: the app stages its own secret from env FLAG when the boundary runs it.
        self.app_rel = self.challenge.get("app_rel", "app.py")
        self.port = port
        # Phase 21 (optional; absent -> the Phase 19 synthetic stdlib defaults): single-service launch
        # kind + a private (black-box) source tree + a service-owned staged flag file.
        self.launch = self.challenge.get("launch", "stdlib")
        self.source_mode = self.challenge.get("source_mode", "public")
        self.flag_file = self.challenge.get("flag_file", "")
        self.flag_token = self.challenge.get("flag_token", "")
        self.docroot = self.challenge.get("docroot", "")
        self.router = self.challenge.get("router", "")
        if self.launch in ("stdlib", "flask") and not (self.challenge_dir / "tree" / self.app_rel).exists():
            raise FileNotFoundError(f"web instance missing tree/{self.app_rel} in {self.challenge_dir}")
        self.elog.append_event("web_service_harness_ready", app_rel=self.app_rel, port=self.port,
                               launch=self.launch, source_mode=self.source_mode)

    def _boot_flag(self):
        """The runner stages the per-run flag at <set>/_boot/<run_id>/flag (self.run_dir is
        <set>/<run_id>/harness)."""
        realrun = self.run_dir.parent.name
        root = self.run_dir.parent.parent
        return (root / "_boot" / realrun / "flag").read_text()

    def run_experiment(self, spec):
        name = spec["name"]
        exp_id = f"{self.challenge_id}-{name}"
        ok, reason = self.check_budget()
        if not ok:
            self.elog.append_event("experiment_blocked", experiment_id=exp_id, blocked_by=reason)
            outcome = ExperimentOutcome(exp_id, "aborted", "", "", "none", False, "", False)
            self.experiments[exp_id] = self._exp_record(outcome, blocked_by=reason)
            self._save()
            return outcome

        # Persist each experiment's code so a later history-free reproduce can replay the WINNING one
        # (web_service overwrites /work/exp.py every run, like the pwn boundary; mirror the P34 pwn fix).
        (self.run_dir / "exp_code").mkdir(exist_ok=True)
        (self.run_dir / "exp_code" / f"{name}.py").write_text(spec["code"])

        timeout = spec.get("timeout", 60)
        t0 = self.clock()
        res = web_service.run(self.run_dir, self.challenge_dir, self._boot_flag(), spec["code"],
                              app_rel=self.app_rel, port=self.port, exp_name=name, exp_id=exp_id,
                              image=self.image, wall_s=timeout, write_record=False,
                              launch=self.launch, source_mode=self.source_mode,
                              flag_file=self.flag_file, flag_token=self.flag_token,
                              docroot=self.docroot, router=self.router)
        self.budget_spent["attempts"] += 1
        self.budget_spent["time_s"] += self.clock() - t0

        rec = res["rec"]
        self.experiments[exp_id] = rec
        with open(self.run_dir / "experiments.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self.elog.command_seq += 1
        cmd = {"seq": self.elog.command_seq, "experiment_id": exp_id, "tool": "web-service",
               "version": self.image, "argv": ["boundary", name], "input_files": [self.app_rel],
               "env": {}, "cwd": "/work", "timeout": timeout, "nondeterministic": True,
               "dedup_key": "", "execution_status": rec["execution_status"],
               "observation": res["stdout"][:4096]}
        with open(self.run_dir / "commands.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(cmd, sort_keys=True) + "\n")
        self.elog.append_event("experiment_executed", experiment_id=exp_id,
                               execution_status=rec["execution_status"], sandbox_profile="container",
                               profile_variant=rec["profile_variant"], network_guaranteed=True)
        self._save()
        return ExperimentOutcome(exp_id, rec["execution_status"], res["stdout"], rec["stdout_ref"],
                                 "container", True, "", False)
