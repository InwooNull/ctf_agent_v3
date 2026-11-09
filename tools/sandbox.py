"""Isolation layer for single tool executions.

What is *actually enforced* with the current host (Python stdlib + the
`unshare` binary), and what is not, is reported honestly by `capabilities()`
and recorded per execution in the result's `sandbox_profile`:

  path jail      : argv paths and cwd are resolved and must stay inside the
                   jail root; escaping paths are rejected before exec. This
                   guards the *interface* (what we hand the tool), not what a
                   hostile binary might open on its own — full FS confinement
                   needs a mount namespace or docker (not wired this phase).
  rlimits        : resource.setrlimit for CPU seconds, address space, and
                   output file size, applied in the child via preexec_fn.
  wall timeout   : subprocess timeout kills the process group.
  network off    : enforced for real via a user+net namespace (`unshare
                   --user --map-root-user --net`) when that backend is
                   available; otherwise network is NOT guaranteed and the
                   profile is marked accordingly.

docker is present on this host and is a stronger backend, but this phase wires
only the stdlib/unshare path; `capabilities()` reports docker as available.
"""
import json
import os
import resource
import shutil
import signal
import subprocess
from pathlib import Path

# profiles
PROFILE_NETNS = "netns"        # network blocked via user+net namespace
PROFILE_RLIMIT = "rlimit"      # rlimit + path jail only; network NOT guaranteed
PROFILE_READONLY_UTILS = "readonly-utils"  # alias: prefer netns, fall back to rlimit
PROFILE_CONTAINER = "container"            # docker: full FS + network + resource isolation
PROFILE_CONTAINER_UNAVAILABLE = "container-unavailable"

SANDBOX_CONFIG = Path(__file__).resolve().parents[1] / "config" / "sandbox.json"

_NETNS_SMOKE = ["unshare", "--user", "--map-root-user", "--net", "--", "true"]


def _unshare_netns_works():
    if shutil.which("unshare") is None:
        return False
    try:
        p = subprocess.run(_NETNS_SMOKE, capture_output=True, timeout=10)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def load_sandbox_config(path=None):
    with open(path or SANDBOX_CONFIG, encoding="utf-8") as f:
        return json.load(f)


def docker_available():
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def image_available(image):
    if shutil.which("docker") is None:
        return False
    try:
        p = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=20)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def container_backend_ready(image=None):
    """docker daemon is up AND the configured image is already present locally."""
    if not docker_available():
        return False
    if image is None:
        try:
            image = load_sandbox_config()["container"]["image"]
        except (OSError, KeyError, ValueError):
            return False
    return image_available(image)


def capabilities():
    """Probe isolation backends actually usable right now."""
    netns = _unshare_netns_works()
    docker_ok = docker_available()
    try:
        image = load_sandbox_config()["container"]["image"]
    except (OSError, KeyError, ValueError):
        image = None
    img_ok = image_available(image) if (docker_ok and image) else False
    return {
        "docker": docker_ok,
        "container_image": image,
        "container_image_present": img_ok,
        "container_backend_ready": docker_ok and img_ok,
        "unshare_netns": netns,
        "rlimit": True,                                  # stdlib, always available
        "network_block_guaranteed": netns,
    }


def resolve_profile(requested, caps=None):
    """Map a tool's requested profile to what can actually be enforced.

    Returns (profile_name, network_guaranteed).
      container       -> container when the docker backend + image are ready,
                         else container-unavailable (run_tool refuses untrusted).
      netns / readonly-utils -> netns when the namespace backend works, else
                         rlimit with network NOT guaranteed (trusted utils only).
      rlimit          -> rlimit.
    """
    caps = caps or capabilities()
    if requested == PROFILE_CONTAINER:
        if caps["container_backend_ready"]:
            return PROFILE_CONTAINER, True
        return PROFILE_CONTAINER_UNAVAILABLE, False
    if requested in (PROFILE_NETNS, PROFILE_READONLY_UTILS) and caps["unshare_netns"]:
        return PROFILE_NETNS, True
    return PROFILE_RLIMIT, False


def build_container_argv(inner_argv, jail_root, container_cfg, name, input_dir=None,
                         timeout=None):
    """Build the locked-down `docker run` argv for the container profile.

    Enforced flags: --network none, --read-only root FS, rw bind workdir (-> host
    jail so outputs persist), optional :ro input mount, non-root --user, --cap-drop
    ALL, --security-opt no-new-privileges, --memory/--cpus/--pids-limit/--ulimit
    fsize, --rm. No host path is mounted except the explicit workdir and input.
    """
    c = container_cfg
    lim = c.get("limits", {})
    user = c.get("user", "host")
    if user == "host":
        user = f"{os.getuid()}:{os.getgid()}"
    argv = ["docker", "run", "--rm", "--name", name,
            "--network", c.get("network", "none")]
    if c.get("read_only_root", True):
        argv.append("--read-only")
    for cap in c.get("cap_drop", ["ALL"]):
        argv += ["--cap-drop", cap]
    if c.get("no_new_privileges", True):
        argv += ["--security-opt", "no-new-privileges"]
    argv += ["--user", str(user),
             "-v", f"{os.path.realpath(jail_root)}:{c['container_workdir']}:rw",
             "-w", c["container_workdir"]]
    if input_dir is not None:
        argv += ["-v", f"{os.path.realpath(input_dir)}:{c['container_input']}:ro"]
    if "memory" in lim:
        argv += ["--memory", str(lim["memory"]), "--memory-swap", str(lim["memory"])]
    if "cpus" in lim:
        argv += ["--cpus", str(lim["cpus"])]
    if "pids_limit" in lim:
        argv += ["--pids-limit", str(lim["pids_limit"])]
    if "fsize_bytes" in lim:
        argv += ["--ulimit", f"fsize={int(lim['fsize_bytes'])}"]
    argv += [c["image"], *inner_argv]
    return argv


def classify_container_status(return_code, timed_out):
    """Map a `docker run` exit code to an execution_status.

    timeout : we killed the container for exceeding the wall clock.
    aborted : the process was killed by a signal inside the container
              (137 = SIGKILL/OOM, 128+n = other signals such as SIGXFSZ).
    ok      : exit 0.
    error   : any other non-zero exit (program error, docker usage error).
    """
    if timed_out:
        return "timeout"
    if return_code == 0:
        return "ok"
    if return_code == 137 or (isinstance(return_code, int) and return_code > 128):
        return "aborted"
    return "error"


def build_argv(inner_argv, profile):
    """Wrap the tool argv with the isolation backend for the chosen profile."""
    if profile == PROFILE_NETNS:
        return ["unshare", "--user", "--map-root-user", "--net", "--", *inner_argv]
    return list(inner_argv)


def make_preexec(limits):
    """Return a preexec_fn applying rlimits and a fresh process group in the child.

    limits: {cpu_s, mem_bytes, file_bytes} (any may be None to leave default).
    CPU uses soft==hard: with soft<hard the kernel only delivers SIGXCPU at the
    soft limit, which was observed not to terminate the child on this host, so
    the hard limit (SIGKILL) must coincide. SIGXCPU/SIGXFSZ are reset to default
    disposition so the limit terminates the child instead of being ignored.
    """
    cpu_s = limits.get("cpu_s")
    mem_bytes = limits.get("mem_bytes")
    file_bytes = limits.get("file_bytes")

    def preexec():
        os.setsid()
        signal.signal(signal.SIGXCPU, signal.SIG_DFL)
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
        if cpu_s is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (int(cpu_s), int(cpu_s)))
        if mem_bytes is not None:
            resource.setrlimit(resource.RLIMIT_AS, (int(mem_bytes), int(mem_bytes)))
        if file_bytes is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (int(file_bytes), int(file_bytes)))

    return preexec


def classify_status(return_code, timed_out):
    """Map a finished process to an execution_status.

    timeout : we killed it for exceeding the wall clock.
    aborted : terminated by a signal (rlimit SIGXCPU/SIGKILL/SIGXFSZ, etc).
    ok      : exit 0.
    error   : non-zero exit (includes a tool refusing an operation at an rlimit
              ceiling, e.g. MemoryError / EFBIG).
    """
    if timed_out:
        return "timeout"
    if return_code is not None and return_code < 0:
        return "aborted"
    return "ok" if return_code == 0 else "error"
