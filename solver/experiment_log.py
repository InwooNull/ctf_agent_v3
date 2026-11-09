"""Experiment/event logging and dedup cache.

- events.jsonl   : append-only event log ({"seq", "kind", ...}).
- commands.jsonl : one record per *actual* execution ({"seq", "dedup_key", ...}).
The dedup cache is rebuilt from commands.jsonl on load, so it survives resume.
"""
import hashlib
import json
import os
from pathlib import Path

# Only successful runs are cached. error/timeout/aborted may be transient
# (a crash, a resource limit, a flaky dependency) so they are never served
# from cache and are always retried.
CACHEABLE_STATUSES = ("ok",)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def file_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return f"missing:{path}"


def compute_dedup_key(tool, version, argv, input_files=(), env=None, timeout=None, cwd="."):
    """hash(tool + version + argv[] + input_file_hashes + relevant env + timeout + cwd)."""
    payload = {
        "tool": tool,
        "version": version,
        "argv": list(argv),
        "input_file_hashes": [file_sha256(p) for p in input_files],
        "env": dict(env or {}),
        "timeout": timeout,
        "cwd": cwd,
    }
    return hashlib.sha256(_canonical(payload).encode()).hexdigest()


def enforce_judgment_separation(execution_status, judgment):
    """A failed tool run must never count as evidence for or against a hypothesis."""
    if execution_status == "ok":
        return judgment
    return "deferred" if execution_status == "aborted" else "inconclusive"


def _read_jsonl(path):
    if not path.exists():
        return []
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # torn trailing line from a crash
    return records


def _append_jsonl(path, record):
    with open(path, "a", encoding="utf-8") as f:
        f.write(_canonical(record) + "\n")


class ExperimentLog:
    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.run_dir / "events.jsonl"
        self.commands_path = self.run_dir / "commands.jsonl"
        self.event_seq = 0
        self.command_seq = 0
        self._cache = {}
        for ev in _read_jsonl(self.events_path):
            self.event_seq = max(self.event_seq, ev["seq"])
        for rec in _read_jsonl(self.commands_path):
            self.command_seq = max(self.command_seq, rec["seq"])
            self._remember(rec)

    def _remember(self, rec):
        if not rec["nondeterministic"] and rec["execution_status"] in CACHEABLE_STATUSES:
            self._cache[rec["dedup_key"]] = rec

    def reconcile(self, committed_event_seq, committed_command_seq):
        """Drop log entries that were appended after the last committed checkpoint.

        A crash can happen after an event/command line is written but before
        state.json is re-saved. On resume we truncate both logs back to the seqs
        recorded in the checkpoint, so replaying the pending action does not
        duplicate entries. The dedup cache is then rebuilt from the kept commands.
        """
        self._truncate(self.events_path, committed_event_seq)
        self._truncate(self.commands_path, committed_command_seq)
        self.event_seq = committed_event_seq
        self.command_seq = committed_command_seq
        self._cache = {}
        for rec in _read_jsonl(self.commands_path):
            self._remember(rec)

    @staticmethod
    def _truncate(path, max_seq):
        if not path.exists():
            return
        kept = [r for r in _read_jsonl(path) if r["seq"] <= max_seq]
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for r in kept:
                f.write(_canonical(r) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def append_event(self, kind, **data):
        self.event_seq += 1
        _append_jsonl(self.events_path, {"seq": self.event_seq, "kind": kind, **data})
        return self.event_seq

    def run(self, experiment_id, spec, execute):
        """Run spec via execute(spec) -> (execution_status, observation), or serve from cache.

        Returns {"dedup_key", "execution_status", "observation", "observation_ref", "cached"}.
        """
        key = compute_dedup_key(
            spec["tool"], spec.get("version", ""), spec["argv"], spec.get("input_files", ()),
            spec.get("env"), spec.get("timeout"), spec.get("cwd", "."),
        )
        nondeterministic = bool(spec.get("nondeterministic", False))
        hit = None if nondeterministic else self._cache.get(key)
        if hit is not None:
            ref = f"commands.jsonl#{hit['seq']}"
            self.append_event("dedup_hit", experiment_id=experiment_id, dedup_key=key, observation_ref=ref)
            return {"dedup_key": key, "execution_status": hit["execution_status"],
                    "observation": hit["observation"], "observation_ref": ref, "cached": True}

        status, observation = execute(spec)
        self.command_seq += 1
        rec = {
            "seq": self.command_seq,
            "experiment_id": experiment_id,
            "tool": spec["tool"],
            "version": spec.get("version", ""),
            "argv": list(spec["argv"]),
            "input_files": list(spec.get("input_files", ())),
            "env": dict(spec.get("env") or {}),
            "cwd": spec.get("cwd", "."),
            "timeout": spec.get("timeout"),
            "nondeterministic": nondeterministic,
            "dedup_key": key,
            "execution_status": status,
            "observation": observation,
        }
        _append_jsonl(self.commands_path, rec)
        self._remember(rec)
        ref = f"commands.jsonl#{rec['seq']}"
        self.append_event("experiment_executed", experiment_id=experiment_id, dedup_key=key,
                          execution_status=status, observation_ref=ref)
        return {"dedup_key": key, "execution_status": status, "observation": observation,
                "observation_ref": ref, "cached": False}
