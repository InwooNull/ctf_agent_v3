"""Harness that runs each experiment on the Phase 13 pwn-service 2-uid boundary.

Same reasoner-facing API as CryptoHarness (run_experiment / report_candidate / get_state /
check_budget; experiments/candidates/state logs) so eval/c0_cli.py drives it unchanged, but every
experiment is one 2-uid --network none container (tools.pwn_service.run): the agent code runs as the
agent uid with the public binary at /input and the flag-bearing target reachable only over the loopback
service. The flag is staged by the runner at store/<set>/_boot/<run_id>/flag (readable by the harness
process, never mounted to the agent); blindness for it rests on the in-container boundary + the CLI-only
transcript audit + the atime trap (a same-uid subagent cannot be walled off by file mode alone).
"""
import json
import time
from pathlib import Path

from solver.crypto_harness import CryptoHarness, ExperimentOutcome
from solver import pwn_deploy
from tools import pwn_service

# Default image. Resolved at call time (not bound as a default arg) so a runner/CLI can switch it —
# e.g. the pwndbg-free C0 baseline forces 0.1, while a pwndbg increment config uses 0.2.
PWN_IMAGE = "ctfagent-pwn:0.2"


class PwnServiceHarness(CryptoHarness):
    def __init__(self, run_id, challenge_dir, store_root=None, budget=None, image=None, clock=None):
        image = image or PWN_IMAGE
        super().__init__(run_id, challenge_dir, store_root=store_root, budget=budget, image=image, clock=clock)
        # Resolve the public challenge dir into a clean deploy dir ONCE (host-side; safe on untrusted
        # archives). The deploy dir (real ELF + shipped libs + manifest) is mounted at /input; the
        # boundary reconstructs the service tree from it. See solver/pwn_deploy.py.
        self.deploy_dir = self.run_dir / "deploy"
        if (self.deploy_dir / "deploy.json").exists():
            self.manifest = json.loads((self.deploy_dir / "deploy.json").read_text())
        else:
            self.manifest = pwn_deploy.resolve(self.challenge_dir, self.deploy_dir,
                                               challenge=self.challenge)
        self.binname = self.manifest["target_rel"].rsplit("/", 1)[-1]
        self.elog.append_event("pwn_service_harness_ready", binname=self.binname,
                               deploy=self.manifest.get("notes"))

    def _boot_flag(self):
        """The runner stages the per-run flag at <set>/_boot/<run_id>/flag (self.run_dir is
        <set>/<run_id>/harness)."""
        realrun = self.run_dir.parent.name
        root = self.run_dir.parent.parent
        p = root / "_boot" / realrun / "flag"
        return p.read_text()

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

        timeout = spec.get("timeout", 60)
        t0 = self.clock()
        # Persist each experiment's code (the boundary overwrites work/exp.py per run), so a clean
        # history-free reproduce step (Phase 34) can replay the winning exploit by name.
        code_dir = self.run_dir / "exp_code"
        code_dir.mkdir(parents=True, exist_ok=True)
        (code_dir / f"{name}.py").write_text(spec["code"])
        res = pwn_service.run(self.run_dir, self.deploy_dir, self.binname, self._boot_flag(),
                              spec["code"], manifest=self.manifest, exp_name=name, exp_id=exp_id,
                              image=self.image, wall_s=timeout, write_record=False)
        self.budget_spent["attempts"] += 1
        self.budget_spent["time_s"] += self.clock() - t0

        rec = res["rec"]
        # record in the CryptoHarness experiments.jsonl shape the verifier reads
        self.experiments[exp_id] = rec
        with open(self.run_dir / "experiments.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self.elog.command_seq += 1
        cmd = {"seq": self.elog.command_seq, "experiment_id": exp_id, "tool": "pwn-service",
               "version": self.image, "argv": ["boundary", name], "input_files": [self.binname],
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
