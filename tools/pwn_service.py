"""pwn-service sandbox profile: a single container, two unprivileged uids, --network none.

Why: real pwn flags live in a server-side flag.txt. If the agent's experiment and the target run as
the same uid, the agent can just read flag.txt and fake a SOLVED. This profile puts flag.txt behind a
uid boundary inside one --network none container:

  * The container starts as root with cap-drop ALL + only SETUID/SETGID/CHOWN. A root init
    (boundary_init) reconstructs the service tree on tmpfs /srv, places the real flag where the binary
    expects it (owned by the SERVICE uid, mode 640), then SCRUBS the flag from its environment.
  * A tiny loopback forwarder runs as the SERVICE uid on 127.0.0.1:PORT, forking the target per
    connection (from the binary's own cwd, with its shipped runtime) — no socat, no external network.
    (If the binary binds its own port, it is run directly as the SERVICE uid instead.)
  * The agent experiment runs as the AGENT uid (= host uid) from /work, PR_SET_NO_NEW_PRIVS set, and can
    reach the target only over the loopback tube. It cannot read, traverse, or chown its way to the flag.

Phase 15: the target, its cwd, its shipped libraries, and the flag's path are no longer hard-coded.
When /input/deploy.json is present (produced by solver.pwn_deploy) the init honours it: it mirrors the
extracted tree, runs the real ELF (not an archive/.c/lib) from its own directory under the shipped
loader or LD_LIBRARY_PATH, and stages the flag at every path the binary might open (the decoy flag
files, the cwd, and absolute /flag.txt — the last needs a writable rootfs, so --read-only is dropped
for this profile; confidentiality still rests on the uid+mode boundary, re-proven by the boundary test).
Without deploy.json it falls back to the Phase 13 behaviour (copy /input/<bin> -> /srv/target, cwd /srv).

The result is recorded with sandbox_profile="container" plus profile_variant="pwn-service", so
solver/verifier.py's container-evidence rule applies unchanged.
"""
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

PROFILE = "pwn-service"
DEFAULT_PORT = 9999
SESSION_SRC = Path(__file__).resolve().parents[1] / "solver" / "session.py"

# ---- in-container scripts (run as root, then dropped) ------------------------

BOUNDARY_INIT = r'''
import os, sys, json, shutil, socket, time, signal, ctypes
AGENT = int(os.environ["AGENT_UID"])
SERVICE = int(os.environ["SERVICE_UID"])
PORT = int(os.environ["PORT"])
FLAG = os.environ["FLAG"]
libc = ctypes.CDLL(None, use_errno=True)

def drop(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    libc.prctl(38, 1, 0, 0, 0)          # PR_SET_NO_NEW_PRIVS

def ensure_etc_users():
    # Minimal /etc/passwd + /etc/group so getpwuid()/getgrgid() succeed for the service and agent
    # uids. Some runtimes (e.g. GNUstep: NSUserName -> getpwuid) abort during init when their uid has
    # no passwd entry; env USER/HOME do NOT satisfy getpwuid(). We append only the missing numeric
    # uids with generic names and no secrets, as root (rootfs is writable), before any privilege drop.
    want = [(0, "root", "/root"), (SERVICE, "ctfsvc", "/tmp"), (AGENT, "ctfagent", "/work")]
    try:
        passwd = open("/etc/passwd").read()
    except OSError:
        passwd = ""
    add = [f"{nm}:x:{uid}:{uid}:{nm}:{home}:/bin/sh"
           for uid, nm, home in want if f":x:{uid}:" not in passwd]
    if add:
        try:
            open("/etc/passwd", "a").write("\n".join(add) + "\n")
        except OSError:
            pass
    try:
        group = open("/etc/group").read()
    except OSError:
        group = ""
    gadd = [f"{nm}:x:{uid}:" for uid, nm, _ in want if f":x:{uid}:" not in group]
    if gadd:
        try:
            open("/etc/group", "a").write("\n".join(gadd) + "\n")
        except OSError:
            pass

ensure_etc_users()

# The container root has cap-drop ALL + only SETUID/SETGID/CHOWN -> no CAP_DAC_OVERRIDE and no
# CAP_FOWNER. So root cannot traverse or write a service-owned dir, and cannot chmod after chown.
# The uid boundary therefore guards ONLY the flag files: they are mode 640 owned by the service uid,
# reached through world-traversable (0755, root-owned) parent dirs. The public binary, libs and the
# directory tree stay root-owned and world-readable/executable (they are public anyway), which keeps
# both the service uid and the agent uid able to run/read them while the flag content stays secret.

def put_flag(path):
    try:
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)      # created root-owned 0755: traversable by all
        with open(path, "w") as f:
            f.write(FLAG)
        os.chmod(path, 0o640)                  # chmod BEFORE chown (no CAP_FOWNER after)
        os.chown(path, SERVICE, SERVICE)       # agent uid is neither owner nor group -> cannot read
    except OSError:
        pass

os.makedirs("/srv", exist_ok=True)
os.chmod("/srv", 0o755)
mani_path = "/input/deploy.json"
if os.path.exists(mani_path):
    mani = json.load(open(mani_path))
    # 1. mirror the extracted tree onto writable tmpfs /srv/tree (root-owned, world-readable)
    shutil.copytree("/input/tree", "/srv/tree")
    if os.path.isdir("/input/libs"):
        shutil.copytree("/input/libs", "/srv/libs")
    target = "/srv/tree/" + mani["target_rel"]
    cwd = "/srv/tree/" + mani["run_cwd_rel"] if mani["run_cwd_rel"] != "." else "/srv/tree"
    os.chmod(target, 0o755)
    # 2. stage the real flag everywhere the binary might open it (service-owned 640). This MUST run
    # while the dirs are still root-owned: root has no CAP_DAC_OVERRIDE, so it could not create the
    # flag inside a service-owned dir. The companion/service-writable chowns happen AFTER (step 2b).
    for rel in mani.get("flag_decoys", []):
        put_flag("/srv/tree/" + rel)
    for p in (cwd + "/flag", cwd + "/flag.txt", "/srv/flag", "/srv/flag.txt",
              "/srv/tree/flag", "/srv/tree/flag.txt", "/flag", "/flag.txt"):
        put_flag(p)
    # 2b. companion-file staging: make the service's runtime dir (and any manifest-listed dirs)
    # OWNED+WRITABLE by the service uid, so a binary that creates its own companion/runtime files at
    # startup (e.g. cookies.txt, oracle.txt) can. Done AFTER flag staging so root could stage the
    # flag first. This never exposes the flag: the flag files stay 640 service-owned (a dir-owner
    # change does not alter them), and a service-writable cwd does not help the AGENT uid read them.
    for d in [cwd] + ["/srv/tree/" + r for r in mani.get("service_writable", [])]:
        try:
            if os.path.isdir(d):
                os.chown(d, SERVICE, SERVICE)
                os.chmod(d, 0o755)
        except OSError:
            pass
    for rel in mani.get("companion_files", []):
        try:
            os.chmod("/srv/tree/" + rel, 0o644)      # public companion input, world-readable
        except OSError:
            pass
    # 3. build the run spec (how the service execs the target). USER/LOGNAME/HOME let runtimes that
    # call getpwuid()/NSUserName work when the service uid has no /etc/passwd entry (e.g. GNUstep).
    env = dict(TERM="xterm", USER="ctf", LOGNAME="ctf", HOME="/tmp")
    if mani["lib_mode"] == "shipped_ld":
        argv = ["/srv/libs/" + mani["interp"], "--library-path", "/srv/libs", target]
    elif mani["lib_mode"] == "ldpath":
        argv = [target]; env["LD_LIBRARY_PATH"] = "/srv/libs"
    else:
        argv = [target]
    runspec = {"argv": argv, "cwd": cwd, "env": env, "binds_port": mani.get("binds_port")}
else:
    # legacy single-binary path (Phase 13 behaviour)
    shutil.copyfile("/input/" + os.environ["TARGET_BIN"], "/srv/target")
    os.chmod("/srv/target", 0o755)
    put_flag("/srv/flag.txt"); put_flag("/srv/flag"); put_flag("/flag.txt")
    runspec = {"argv": ["/srv/target"], "cwd": "/srv", "env": {"TERM": "xterm"}, "binds_port": None}

with open("/srv/runspec.json", "w") as f:        # root-owned, world-readable (not secret)
    json.dump(runspec, f)

# Place an exec-able debug copy of the (public) target binary at /dbg/target so the AGENT can run it
# under gdb/pwndbg (/work is noexec, /input read-only). runspec["argv"][-1] is the resolved target in
# every branch (deploy/shipped_ld/ldpath/legacy). Copy shipped libs too so a local run uses the right
# runtime. The FLAG is NEVER written to /dbg -> the agent gains a debuggable binary, not flag access
# (confidentiality still rests on the 640 service-owned flag under /srv and absolute paths).
try:
    os.makedirs("/dbg", exist_ok=True)
    shutil.copyfile(runspec["argv"][-1], "/dbg/target")
    os.chmod("/dbg/target", 0o755)
    if os.path.isdir("/srv/libs") and not os.path.exists("/dbg/libs"):
        shutil.copytree("/srv/libs", "/dbg/libs")
except OSError:
    pass

del os.environ["FLAG"]                   # scrub: no child inherits the flag

binds_port = runspec.get("binds_port")

# --- service as SERVICE uid: either a loopback stdio forwarder, or the target itself if it binds ---
svc = os.fork()
if svc == 0:
    drop(SERVICE)
    # binds_port is not None (incl. 0 = "binds its own port, number unknown") means the target opens
    # and accepts on its OWN socket — a forking/own-port server. Run it DIRECTLY from its cwd so its
    # per-connection banner/handshake reaches the agent natively (routing such a server through the
    # stdio forwarder loses the banner, since it writes to its bound socket, not stdout). PORT is
    # passed in the env so a server that honours $PORT binds the port the agent will connect to.
    if binds_port is not None:
        os.chdir(runspec["cwd"])
        e = dict(os.environ); e.update(runspec["env"]); e["PORT"] = str(PORT)
        os.execve(runspec["argv"][0], runspec["argv"], e)
    else:
        os.chdir("/srv")
        os.execv(sys.executable, [sys.executable, "-I", "/work/service.py"])
    os._exit(127)

def _listening_ports():
    # LISTEN sockets from /proc/net/tcp{,6} (state 0A). --network none => the only listeners are ours.
    ports = set()
    for pf in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in open(pf).read().splitlines()[1:]:
                f = line.split()
                if len(f) > 3 and f[3] == "0A":
                    ports.add(int(f[1].rsplit(":", 1)[1], 16))
        except OSError:
            pass
    return ports

# An own-port server (binds_port is not None) may bind a HARD-CODED port that ignores $PORT. Discover
# the port it actually bound and, if it is not PORT, run a service-uid TCP relay PORT -> bound_port so
# the agent always reaches it at the advertised 127.0.0.1:PORT (this is what fixes a forking own-port
# server whose banner never reached the agent). Single bytes are proxied verbatim, so the handshake is
# preserved; the server still forks per connection (one in-flight attempt per connect, unchanged).
if binds_port is not None:
    bound = None
    for _ in range(200):
        live = _listening_ports()
        if PORT in live:
            bound = PORT; break
        cand = sorted(live)
        if cand:
            bound = cand[0]; break
        time.sleep(0.05)
    if bound is not None and bound != PORT:
        rl = os.fork()
        if rl == 0:
            drop(SERVICE)
            os.execv(sys.executable, [sys.executable, "-I", "/work/relay.py", str(PORT), str(bound)])
            os._exit(127)

probe_port = PORT
for _ in range(200):
    try:
        s = socket.create_connection(("127.0.0.1", probe_port), timeout=0.2); s.close(); break
    except OSError:
        time.sleep(0.05)

# --- agent experiment as AGENT uid ---
# The agent runs via a wrapper so IT (the owner of /work) writes agent.rc: root here has no
# CAP_DAC_OVERRIDE and cannot create files in the agent-owned /work.
ag = os.fork()
if ag == 0:
    drop(AGENT)
    # HOME=/dbg (writable, world-traversable tmpfs) so tools the agent spawns resolve a usable home.
    # Critically this stops pwndbg's gdbinit find_poetry() from doing Path("~/.local/bin/poetry")
    # .exists() against /root (0700) and raising PermissionError -> without this pwndbg fails to load
    # for the agent uid entirely. With HOME=/dbg it loads cleanly (the poetry check returns None).
    os.environ["HOME"] = "/dbg"
    os.environ["USER"] = "ctfagent"
    os.environ["LOGNAME"] = "ctfagent"
    os.chdir("/work")
    out = os.open("/work/agent.out", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    err = os.open("/work/agent.err", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.dup2(out, 1); os.dup2(err, 2)
    os.execv(sys.executable, [sys.executable, "-I", "/work/agent_wrap.py"])
    os._exit(127)
_, status = os.waitpid(ag, 0)
try:
    os.kill(svc, signal.SIGKILL)
except OSError:
    pass
sys.exit(0)
'''

SERVICE_FWD = r'''
import os, sys, json, socket, signal
PORT = int(os.environ["PORT"])
spec = json.load(open("/srv/runspec.json"))
signal.signal(signal.SIGCHLD, signal.SIG_IGN)   # auto-reap forked targets (no zombies)
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(16)
while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    if os.fork() == 0:
        srv.close()
        os.dup2(conn.fileno(), 0); os.dup2(conn.fileno(), 1); os.dup2(conn.fileno(), 2)
        os.chdir(spec["cwd"])
        e = dict(os.environ); e.update(spec.get("env", {}))
        # stdbuf: force the target's libc stdio unbuffered so prompts flush over the
        # socket (a raw socket is not a tty, so default full buffering would hang recv).
        os.execve("/usr/bin/stdbuf", ["stdbuf", "-i0", "-o0", "-e0"] + spec["argv"], e)
        os._exit(127)
    conn.close()
'''

RELAY_FWD = r'''
import os, sys, socket, signal, select
LISTEN, DST = int(sys.argv[1]), int(sys.argv[2])
signal.signal(signal.SIGCHLD, signal.SIG_IGN)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", LISTEN)); srv.listen(16)
while True:
    try:
        c, _ = srv.accept()
    except OSError:
        break
    if os.fork() == 0:
        srv.close()
        try:
            u = socket.create_connection(("127.0.0.1", DST), timeout=5)
        except OSError:
            os._exit(0)
        pair = [c, u]
        while True:
            r, _, _ = select.select(pair, [], [], 30)
            if not r:
                break
            stop = False
            for s in r:
                try:
                    d = s.recv(65536)
                except OSError:
                    stop = True; break
                if not d:
                    stop = True; break
                (u if s is c else c).sendall(d)
            if stop:
                break
        os._exit(0)
    c.close()
'''

_BOOTSTRAP = "import sys as _s\n_s.path.insert(0, '/work/_lib')\ndel _s\n"

# Runs the agent's exp.py as the agent uid and records the real exit code to /work/agent.rc (which
# root could not write). runpy executes exp.py as __main__ so its leading sys.path bootstrap applies.
AGENT_WRAP = r'''
import runpy, sys, traceback
rc = 0
try:
    runpy.run_path("/work/exp.py", run_name="__main__")
except SystemExit as e:
    rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
except BaseException:
    traceback.print_exc()
    rc = 1
try:
    open("/work/agent.rc", "w").write(str(rc))
except OSError:
    pass
sys.exit(0)
'''


def run(run_dir, input_dir, binname, flag, agent_code, *, manifest=None, port=DEFAULT_PORT,
        exp_name="exploit", exp_id=None, image="ctfagent-pwn:0.1", wall_s=180,
        limits=None, agent_uid=None, service_uid=None, write_record=True):
    """Launch the boundary and run `agent_code` (python) as the agent uid. `input_dir` is mounted
    read-only at /input; when it contains deploy.json (from solver.pwn_deploy) the boundary honours the
    manifest, otherwise it falls back to copying /input/<binname>. Returns
    {exp_id, execution_status, stdout, stderr, rc, rec}."""
    run_dir = Path(run_dir)
    jail = run_dir / "work"
    artifacts = run_dir / "artifacts"
    (jail / "_lib").mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    agent_uid = os.getuid() if agent_uid is None else agent_uid
    service_uid = (1001 if agent_uid != 1001 else 1002) if service_uid is None else service_uid
    # fsize 64 MiB: the boundary copies shipped libraries onto /srv (e.g. libicudata.so.52 ~25 MiB),
    # so the per-file write limit must clear the largest bundled lib, not just agent scratch output.
    limits = limits or {"memory": "512m", "pids_limit": 256, "fsize_bytes": 67108864}

    (jail / "_lib" / "session.py").write_text(SESSION_SRC.read_text())
    (jail / "service.py").write_text(SERVICE_FWD)
    (jail / "relay.py").write_text(RELAY_FWD)
    (jail / "boundary_init.py").write_text(BOUNDARY_INIT)
    (jail / "agent_wrap.py").write_text(AGENT_WRAP)
    (jail / "exp.py").write_text(_BOOTSTRAP + agent_code)

    exp_id = exp_id or f"{Path(input_dir).name}-{exp_name}"
    name = f"ctfagent_pwnsvc_{uuid.uuid4().hex[:12]}"
    # NOTE: --read-only is intentionally omitted for this profile: the init must create the flag at an
    # absolute path (e.g. /flag.txt) that some binaries open. Confidentiality rests on the uid+mode
    # boundary (flag is 640 service-owned; agent uid cannot read it), proven by tests/test_pwn_boundary.
    argv = ["docker", "run", "--rm", "--name", name, "--network", "none",
            "--tmpfs", "/srv:rw,exec,mode=0755", "--tmpfs", "/tmp:rw",
            # /dbg: an exec-able, world-accessible scratch for the AGENT to run the target under
            # gdb/pwndbg (/work is a noexec bind mount; /input is read-only). boundary_init copies
            # ONLY the public target binary (+ shipped libs) here, never the flag -> anti-cheat intact.
            "--tmpfs", "/dbg:rw,exec,mode=0777",
            "-v", f"{os.path.realpath(jail)}:/work:rw",
            "-v", f"{os.path.realpath(input_dir)}:/input:ro",
            "-w", "/work", "--user", "0:0",
            "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "CHOWN"]
    if "memory" in limits:
        argv += ["--memory", str(limits["memory"]), "--memory-swap", str(limits["memory"])]
    if "pids_limit" in limits:
        argv += ["--pids-limit", str(limits["pids_limit"])]
    if "fsize_bytes" in limits:
        argv += ["--ulimit", f"fsize={int(limits['fsize_bytes'])}"]
    argv += ["-e", "TERM=xterm", "-e", f"AGENT_UID={agent_uid}", "-e", f"SERVICE_UID={service_uid}",
             "-e", f"PORT={port}", "-e", f"TARGET_BIN={binname}", "-e", f"FLAG={flag}",
             image, "python3", "-I", "/work/boundary_init.py"]

    timed_out = False
    try:
        subprocess.run(argv, capture_output=True, timeout=wall_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(["docker", "kill", name], capture_output=True)

    stdout = (jail / "agent.out").read_text(errors="replace") if (jail / "agent.out").exists() else ""
    stderr = (jail / "agent.err").read_text(errors="replace") if (jail / "agent.err").exists() else ""
    rc_raw = (jail / "agent.rc").read_text().strip() if (jail / "agent.rc").exists() else ""
    rc = int(rc_raw) if rc_raw.isdigit() else None
    status = "timeout" if timed_out else ("ok" if rc == 0 else "error")
    stdout_ref = f"{exp_id}.stdout"
    (artifacts / stdout_ref).write_text(stdout)
    (artifacts / f"{exp_id}.stderr").write_text(stderr)
    rec = {"exp_id": exp_id, "execution_status": status, "sandbox_profile": "container",
           "profile_variant": PROFILE, "network_guaranteed": True, "stdout_ref": stdout_ref,
           "service_uid": service_uid, "agent_uid": agent_uid, "cached": False, "created_files": []}
    if write_record:
        with open(run_dir / "experiments.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
    return {"exp_id": exp_id, "execution_status": status, "stdout": stdout, "stderr": stderr,
            "rc": rc, "rec": rec}


def report_candidate(run_dir, value, evidence_refs):
    with open(Path(run_dir) / "candidates.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"value": value, "evidence_refs": list(evidence_refs),
                            "status": "UNVERIFIED"}, sort_keys=True) + "\n")
