"""Capability probe + smoke test for the tool allowlist and isolation backends.

probe_isolation() reports which sandbox backends are actually usable.
probe_tool()      checks: is the binary present, what version, does a smoke
                  command run through the real sandbox pipeline and produce the
                  expected output.
A tool is "ready" only when present AND its smoke test passes.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path

from tools import run_tool, sandbox


def probe_isolation():
    return sandbox.capabilities()


def local_images():
    """List locally present docker images (no pull)."""
    if shutil.which("docker") is None:
        return []
    try:
        p = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                           capture_output=True, text=True, timeout=20)
        return [ln for ln in p.stdout.splitlines() if ln and "<none>" not in ln]
    except (OSError, subprocess.SubprocessError):
        return []


def probe_container():
    """Report docker availability, the configured image, and whether it is present."""
    caps = sandbox.capabilities()
    return {
        "docker": caps["docker"],
        "configured_image": caps["container_image"],
        "configured_image_present": caps["container_image_present"],
        "backend_ready": caps["container_backend_ready"],
        "local_images": local_images(),
    }


def probe_tool(tool_id, meta, work_dir=None):
    report = {"tool_id": tool_id, "present": False, "version": None,
              "smoke_ok": False, "ready": False, "detail": ""}
    if shutil.which(meta["bin"]) is None:
        report["detail"] = "binary not found on PATH"
        return report
    report["present"] = True
    report["version"] = run_tool._tool_version(tool_id, meta)

    smoke = meta.get("smoke_cmd")
    if not smoke:
        report["smoke_ok"] = True
        report["ready"] = True
        report["detail"] = "no smoke command; presence only"
        return report

    tmp_ctx = None
    if work_dir is None:
        tmp_ctx = tempfile.TemporaryDirectory()
        work_dir = tmp_ctx.name
    try:
        spec = {
            "tool_id": tool_id,
            "argv": smoke,
            "stdin": meta.get("smoke_stdin"),
            "timeout": 15,
            "resource_limits": {"cpu_s": 5, "mem_bytes": 512 * 1024 * 1024, "file_bytes": 4 * 1024 * 1024},
            "network": False,
        }
        artifacts = Path(work_dir) / "artifacts"
        result = run_tool.run_tool(spec, jail_root=work_dir, artifacts_dir=artifacts)
        stdout = _read(artifacts, result.stdout_ref)
        expect = meta.get("smoke_expect")
        if result.execution_status != "ok":
            report["detail"] = f"smoke status={result.execution_status} rc={result.return_code}"
        elif expect is not None and expect not in stdout:
            report["detail"] = f"smoke output mismatch (want {expect!r})"
        elif expect is None and not stdout.strip():
            report["detail"] = "smoke produced no output"
        else:
            report["smoke_ok"] = True
            report["ready"] = True
            report["detail"] = "ok"
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()
    return report


def _read(artifacts_dir, ref):
    # ref is relative to artifacts_dir.parent; take the basename under artifacts_dir
    p = Path(artifacts_dir) / Path(ref).name
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def probe_all(allowlist=None, config_path=None):
    allowlist = allowlist if allowlist is not None else run_tool.load_allowlist(config_path)
    return {
        "isolation": probe_isolation(),
        "container": probe_container(),
        "tools": {tid: probe_tool(tid, meta) for tid, meta in allowlist.items()},
    }


if __name__ == "__main__":
    import json
    print(json.dumps(probe_all(), indent=2))
