"""Cybench network lane — live-target harness for the 18 networked tasks.

The frozen category harnesses run every experiment in a `--network none` sandbox, which
cannot reach a live target. Cybench networked tasks instead ship a docker-compose target on
the shared external network `shared_net`; the competitor exploits it to retrieve the flag
(a standardized placeholder baked into the image). This lane is ADDITIVE — it touches none
of the 7 hash-pinned governance files — and reproduces that setup:

  * up()    : `docker compose -p <proj> up -d` the task's target on `shared_net`
  * run_experiment(spec): run the agent's python (`-I`) in a `ctfagent-<cat>` container
              JOINED to `shared_net`, so it resolves `target_host` and attacks it. stdout is
              captured to artifacts/ and logged in the SAME shape the verifier reads
              (experiments.jsonl: exp_id, execution_status, stdout_ref, sandbox_profile=container).
  * report_candidate(value, refs) -> candidates.jsonl
  * down()  : tear the target down

The flag never reaches this process except as the verifier's sealed scorer key; the harness
only runs the agent's code against the live container. Blindness holds: the agent must
exploit the target to make the flag appear in an experiment's stdout (SRC_TARGET evidence).

  python3 eval/cybench_net_lane.py up    <cid>
  python3 eval/cybench_net_lane.py down  <cid>
  python3 eval/cybench_net_lane.py probe <cid>      # up, GET target, down (smoke)
"""
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CYBENCH_ROOT = Path("/home/inwoo/ctf_benches/cybench")
ARENA = PROJECT_ROOT / "arena" / "cybench"
MANIFEST = ARENA / "_manifest.json"       # public: target info only, no answers
SHARED_NET = "shared_net"
RAN_OK = "ok"


def _manifest():
    return json.loads(MANIFEST.read_text())


def ensure_shared_net():
    r = subprocess.run(["docker", "network", "inspect", SHARED_NET],
                       capture_output=True, text=True)
    if r.returncode != 0:
        subprocess.run(["docker", "network", "create", SHARED_NET],
                       capture_output=True, text=True)


def _compose_file(source_path):
    td = CYBENCH_ROOT / source_path
    for name in ("docker-compose.yml", "compose.yml", "dist/docker-compose.yml",
                 "dist/compose.yml", "challenge/docker-compose.yml"):
        if (td / name).exists():
            return td / name
    return None


class CybenchNetHarness:
    def __init__(self, cid, store_root=None):
        info = _manifest()[cid]
        self.cid = cid
        self.category = info["category"]
        self.target_host = info["target_host"]
        self.source_path = info["source_path"]
        self.image = f"ctfagent-{self.category}:" + {
            "web": "0.3", "crypto": "0.2", "pwn": "0.3", "misc": "0.7", "rev": "0.1",
        }.get(self.category, "latest")
        self.proj = "cb" + cid.split("_")[1]
        self.compose = _compose_file(self.source_path)
        root = Path(store_root) if store_root else PROJECT_ROOT / "store" / "cybench_net"
        self.run_dir = (root / cid).resolve()
        self.work_dir = self.run_dir / "work"
        self.artifacts_dir = self.run_dir / "artifacts"
        for d in (self.run_dir, self.work_dir, self.artifacts_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.exp_path = self.run_dir / "experiments.jsonl"
        self.cand_path = self.run_dir / "candidates.jsonl"
        self._n = 0

    # ---- target lifecycle ----
    def up(self, wait=20):
        if not self.compose:
            raise RuntimeError(f"no compose file for {self.cid} ({self.source_path})")
        ensure_shared_net()
        subprocess.run(["docker", "compose", "-p", self.proj, "-f", str(self.compose),
                        "up", "-d", "--force-recreate"],
                       capture_output=True, text=True, timeout=600)
        # best-effort wait for the service port
        host, _, port = self.target_host.partition(":")
        for _ in range(wait):
            r = subprocess.run(["docker", "run", "--rm", "--network", SHARED_NET, self.image,
                                "python3", "-I", "-c",
                                f"import socket;socket.create_connection(('{host}',{int(port or 80)}),timeout=3)"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                return True
            time.sleep(2)
        return False

    def down(self):
        if self.compose:
            subprocess.run(["docker", "compose", "-p", self.proj, "-f", str(self.compose),
                            "down", "-v"], capture_output=True, text=True, timeout=300)

    # ---- reasoner-facing API (mirrors the frozen harnesses) ----
    def run_experiment(self, spec):
        """spec: {name, code, timeout?}. Runs code as /work/<name>.py in a ctfagent-<cat>
        container joined to shared_net. Returns a dict with exp_id/status/stdout."""
        self._n += 1
        name = spec.get("name", f"exp{self._n}")
        exp_id = f"{self.cid}-{name}"
        timeout = int(spec.get("timeout", 120))
        src = self.work_dir / f"{name}.py"
        src.write_text(spec["code"])
        # mount any provided challenge source read-only at /input (blackbox tasks have none)
        mounts = ["-v", f"{self.work_dir}:/work"]
        arena_dir = ARENA / self.cid
        has_input = any(p.is_file() and p.name != "challenge.json" for p in arena_dir.rglob("*"))
        if has_input:
            mounts += ["-v", f"{arena_dir}:/input:ro"]
        cmd = ["docker", "run", "--rm", "--network", SHARED_NET, "-w", "/work",
               *mounts, self.image, "python3", "-I", f"/work/{name}.py"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
            stdout, status = r.stdout, (RAN_OK if r.returncode == 0 else "error")
            if r.returncode != 0 and r.stderr:
                stdout += "\n--STDERR--\n" + r.stderr
        except subprocess.TimeoutExpired as e:
            stdout, status = (e.stdout or "") + "\n[timeout]", "timeout"
        stdout_rel = f"artifacts/{exp_id}.stdout"
        (self.run_dir / stdout_rel).write_text(stdout or "")
        rec = {"exp_id": exp_id, "execution_status": status, "stdout_ref": stdout_rel,
               "sandbox_profile": "container", "network_guaranteed": False,
               "target_host": self.target_host, "cached": False}
        with self.exp_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        return {"exp_id": exp_id, "execution_status": status, "stdout": stdout}

    def report_candidate(self, value, evidence_refs):
        rec = {"value": value, "evidence_refs": list(evidence_refs), "status": "UNVERIFIED"}
        with self.cand_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    action, cid = sys.argv[1], sys.argv[2]
    h = CybenchNetHarness(cid)
    if action == "up":
        print("up:", h.up(), "target:", h.target_host, "compose:", h.compose)
    elif action == "down":
        h.down(); print("down:", cid)
    elif action == "probe":
        ok = h.up()
        print("up:", ok)
        host, _, port = h.target_host.partition(":")
        scheme = "http" if port in ("80", "8080", "1337") else None
        if scheme:
            out = h.run_experiment({"name": "probe", "timeout": 30, "code": f"""
import urllib.request
try:
    r=urllib.request.urlopen('{scheme}://{h.target_host}/',timeout=8)
    b=r.read()[:200]; print('HTTP',r.status,'len',len(b)); print(b.decode(errors='replace'))
except Exception as e:
    print('ERR',repr(e))
"""})
            print(out["stdout"][:400])
        h.down()
    else:
        print("unknown action", action)


if __name__ == "__main__":
    main()
