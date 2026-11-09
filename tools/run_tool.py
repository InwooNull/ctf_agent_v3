"""Single-shot tool execution: validate -> sandbox -> run -> structured result.

run_tool reports *execution state + observation only*. It never judges a
hypothesis (support/refute/...) — that belongs to the experiment engine.

Security properties enforced here (see tools/sandbox.py for the backend detail):
  - argv must be a list; it is exec'd directly, never through a shell, so shell
    metacharacters (; | $() `` & > <) are passed as literal arguments.
  - tool_id must be in the allowlist (config/tools.json).
  - cwd and every path-like argv token must resolve inside the jail root.
  - env is a whitelist: the child gets a minimal base plus only the keys the
    caller passes, never the parent environment.
"""
import hashlib
import json
import os
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from tools import sandbox

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "tools.json"
DEFAULT_OUTPUT_CAP = 64 * 1024          # bytes kept inline before truncation flag
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


class ToolError(Exception):
    """Raised when a spec is rejected before execution (validation failure)."""


@dataclass
class ToolResult:
    tool_id: str
    execution_id: str
    execution_status: str          # ok | error | timeout | aborted
    return_code: object
    stdout_ref: str
    stderr_ref: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration: float
    resource_usage: dict
    tool_version: str
    reproducibility_level: str     # full | conditional | external_dependent
    sandbox_profile: str
    network_guaranteed: bool
    created_files: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def load_allowlist(path=None):
    with open(path or DEFAULT_CONFIG, encoding="utf-8") as f:
        return json.load(f)["tools"]


def _is_path_like(token):
    return token.startswith(("/", "./", "../", "~")) or os.sep in token or token in (".", "..")


def _within(root, candidate):
    root = os.path.realpath(root)
    cand = os.path.realpath(candidate)
    return cand == root or cand.startswith(root + os.sep)


def _validate_paths(argv, cwd, jail_root):
    if not _within(jail_root, cwd):
        raise ToolError(f"cwd escapes jail: {cwd!r} not inside {jail_root!r}")
    for tok in argv:
        if _is_path_like(tok):
            resolved = tok if os.path.isabs(tok) else os.path.join(cwd, tok)
            if not _within(jail_root, resolved):
                raise ToolError(f"argv path escapes jail: {tok!r}")


def _file_sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


_VERSION_CACHE = {}


def _tool_version(tool_id, meta):
    if tool_id in _VERSION_CACHE:
        return _VERSION_CACHE[tool_id]
    version = "unknown"
    vcmd = meta.get("version_cmd")
    if vcmd:
        try:
            p = subprocess.run(vcmd, capture_output=True, text=True, timeout=10,
                               env=BASE_ENV)
            line = (p.stdout or p.stderr).strip().splitlines()
            version = line[0] if line else "unknown"
        except (OSError, subprocess.SubprocessError):
            version = "unavailable"
    _VERSION_CACHE[tool_id] = version
    return version


def _reproducibility(meta, nondeterministic, network_on, network_guaranteed):
    if network_on or nondeterministic:
        return "external_dependent"
    if meta.get("deterministic") and network_guaranteed:
        return "full"
    return "conditional"


def run_tool(spec, jail_root, artifacts_dir, allowlist=None, config_path=None,
             output_cap=DEFAULT_OUTPUT_CAP, sandbox_config=None):
    """Execute one tool under isolation and return a ToolResult.

    spec keys: tool_id, argv(list), cwd(optional), timeout(optional), stdin(optional str),
               env(optional dict whitelist), resource_limits{cpu_s,mem_bytes,file_bytes},
               network(bool, default False), nondeterministic(bool).
    jail_root    : directory the execution is confined to (cwd + argv paths).
    artifacts_dir: directory for captured stdout/stderr files.
    """
    allowlist = allowlist if allowlist is not None else load_allowlist(config_path)
    tool_id = spec.get("tool_id")
    if tool_id not in allowlist:
        raise ToolError(f"tool_id not in allowlist: {tool_id!r}")
    meta = allowlist[tool_id]

    argv = spec.get("argv")
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise ToolError("argv must be a list of strings (no shell string)")

    jail_root = os.path.realpath(jail_root)
    network_on = bool(spec.get("network", False))
    nondeterministic = bool(spec.get("nondeterministic", False))
    requested = meta.get("sandbox_profile", sandbox.PROFILE_NETNS)
    profile, net_guaranteed = sandbox.resolve_profile(requested)

    # Policy: untrusted code runs only inside a verified container backend.
    trust = meta.get("trust", "trusted")
    if trust == "untrusted" and profile != sandbox.PROFILE_CONTAINER:
        raise ToolError(f"untrusted tool {tool_id!r} requires the container backend "
                        f"(resolved profile={profile!r}); refusing to run")
    if profile == sandbox.PROFILE_CONTAINER_UNAVAILABLE:
        raise ToolError(f"container backend not ready for {tool_id!r}; refusing to run")

    if profile == sandbox.PROFILE_CONTAINER:
        return _run_container(spec, meta, tool_id, argv, jail_root, artifacts_dir,
                              nondeterministic, output_cap, sandbox_config)

    # ---- readonly-utils path (netns / rlimit) --------------------------------
    cwd = os.path.realpath(spec.get("cwd") or jail_root)
    _validate_paths(argv, cwd, jail_root)
    # If the caller wants network OFF but it cannot be guaranteed, keep the flag honest.
    if network_on:
        profile = sandbox.PROFILE_RLIMIT  # running with network = no netns wrapper
        net_guaranteed = False

    inner_argv = [meta["bin"], *argv[1:]] if argv and argv[0] == tool_id else [meta["bin"], *argv]
    full_argv = sandbox.build_argv(inner_argv, profile)

    limits = spec.get("resource_limits") or {}
    preexec = sandbox.make_preexec(limits)

    env = dict(BASE_ENV)
    env.update(spec.get("env") or {})

    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    execution_id = spec.get("execution_id") or f"{tool_id}-{uuid.uuid4().hex[:12]}"
    timeout = spec.get("timeout")
    stdin = spec.get("stdin")

    before = os.listdir(jail_root)
    ru_before = os.times()  # fallback; children rusage captured via wait4 below
    start = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.Popen(
            full_argv, cwd=cwd, env=env, preexec_fn=preexec,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=False,
        )
    except OSError as e:
        raise ToolError(f"failed to start {tool_id!r}: {e}")
    try:
        out, err = proc.communicate(
            input=stdin.encode() if isinstance(stdin, str) else stdin, timeout=timeout)
        return_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            proc.kill()
        out, err = proc.communicate()
        return_code = proc.returncode
    duration = time.monotonic() - start

    status = sandbox.classify_status(return_code, timed_out)

    out_ref, out_trunc = _write_capture(artifacts_dir, execution_id, "stdout", out, output_cap)
    err_ref, err_trunc = _write_capture(artifacts_dir, execution_id, "stderr", err, output_cap)

    after = os.listdir(jail_root)
    created = sorted(set(after) - set(before))

    ru_after = os.times()
    resource_usage = {
        "cpu_user_s": round(ru_after.children_user - ru_before.children_user, 6),
        "cpu_system_s": round(ru_after.children_system - ru_before.children_system, 6),
        "wall_s": round(duration, 6),
    }

    version = _tool_version(tool_id, meta)
    result = ToolResult(
        tool_id=tool_id, execution_id=execution_id, execution_status=status,
        return_code=return_code, stdout_ref=out_ref, stderr_ref=err_ref,
        stdout_truncated=out_trunc, stderr_truncated=err_trunc, duration=round(duration, 6),
        resource_usage=resource_usage, tool_version=version,
        reproducibility_level=_reproducibility(meta, nondeterministic, network_on, net_guaranteed),
        sandbox_profile=profile, network_guaranteed=net_guaranteed, created_files=created,
    )
    return result


_NAME_SAFE = str.maketrans({c: "_" for c in "/:. @"})


def _run_container(spec, meta, tool_id, argv, jail_root, artifacts_dir, nondeterministic,
                   output_cap, sandbox_config=None):
    """Execute a tool inside a locked-down docker container (see sandbox.build_container_argv).

    sandbox_config overrides the container parameters (e.g. a different image);
    defaults to config/sandbox.json's "container" block.
    """
    cfg = (sandbox_config or sandbox.load_sandbox_config())["container"]
    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    execution_id = spec.get("execution_id") or f"{tool_id}-{uuid.uuid4().hex[:12]}"
    # The docker --name must be UNIQUE even when two concurrent runs share an execution_id
    # (e.g. two blind runs of the same challenge both naming an experiment "e01"): a fixed
    # name collides with "container name already in use" and wastes an experiment. Append a
    # fresh uuid so parallel runs never collide (Phase 50a). This changes only the container
    # NAME, not any isolation flag.
    name = f"ctfagent_{execution_id}_{uuid.uuid4().hex[:8]}".translate(_NAME_SAFE)[:200]
    timeout = spec.get("timeout") or cfg.get("default_timeout_s")
    input_dir = spec.get("input_dir")
    stdin = spec.get("stdin")

    inner_argv = [meta["bin"], *argv[1:]] if argv and argv[0] == tool_id else [meta["bin"], *argv]
    docker_argv = sandbox.build_container_argv(inner_argv, jail_root, cfg, name,
                                               input_dir=input_dir, timeout=timeout)

    before = os.listdir(jail_root)
    start = time.monotonic()
    timed_out = False
    proc = subprocess.Popen(
        docker_argv,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(
            input=stdin.encode() if isinstance(stdin, str) else stdin, timeout=timeout)
        return_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(["docker", "kill", name], capture_output=True)
        try:
            out, err = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        return_code = proc.returncode
    duration = time.monotonic() - start

    status = sandbox.classify_container_status(return_code, timed_out)
    out_ref, out_trunc = _write_capture(artifacts_dir, execution_id, "stdout", out, output_cap)
    err_ref, err_trunc = _write_capture(artifacts_dir, execution_id, "stderr", err, output_cap)
    created = sorted(set(os.listdir(jail_root)) - set(before))

    repro = "external_dependent" if nondeterministic else ("full" if meta.get("deterministic") else "conditional")
    return ToolResult(
        tool_id=tool_id, execution_id=execution_id, execution_status=status,
        return_code=return_code, stdout_ref=out_ref, stderr_ref=err_ref,
        stdout_truncated=out_trunc, stderr_truncated=err_trunc, duration=round(duration, 6),
        resource_usage={"wall_s": round(duration, 6), "limits": cfg.get("limits", {})},
        tool_version=f"{cfg['image']}:{meta['bin']}",
        reproducibility_level=repro, sandbox_profile=sandbox.PROFILE_CONTAINER,
        network_guaranteed=True, created_files=created,
    )


def _write_capture(artifacts_dir, execution_id, stream, data, cap):
    data = data or b""
    path = Path(artifacts_dir) / f"{execution_id}.{stream}"
    path.write_bytes(data)
    rel = os.path.relpath(path, Path(artifacts_dir).parent)
    return rel, len(data) > cap


def reproduction_record(spec, result, allowlist=None, config_path=None):
    """Build the commands.jsonl-style record needed to re-run deterministically."""
    allowlist = allowlist if allowlist is not None else load_allowlist(config_path)
    meta = allowlist[spec["tool_id"]]
    input_files = [t for t in spec.get("argv", []) if _is_path_like(t) and os.path.exists(
        t if os.path.isabs(t) else os.path.join(spec.get("cwd", "."), t))]
    return {
        "tool_id": spec["tool_id"],
        "tool_version": result.tool_version,
        "argv": list(spec["argv"]),
        "cwd": spec.get("cwd", "."),
        "timeout": spec.get("timeout"),
        "input_file_hashes": {f: _file_sha256(
            f if os.path.isabs(f) else os.path.join(spec.get("cwd", "."), f)) for f in input_files},
        "execution_status": result.execution_status,
        "return_code": result.return_code,
        "stdout_ref": result.stdout_ref,
        "sandbox_profile": result.sandbox_profile,
        "reproducibility_level": result.reproducibility_level,
    }
