"""web-service sandbox profile: a single container, two unprivileged uids, --network none.

Why: a web flag lives server-side (a DB row, a file outside the web root). If the agent's experiment
and the web app run as the same uid, the agent can just read that file/DB and fake a SOLVED. This
profile puts the secret behind a uid boundary inside one --network none container, reusing the Phase 13
pwn-service design (the web app is the "binds_port" case: it opens its own listening socket):

  * The container starts as root with cap-drop ALL + only SETUID/SETGID/CHOWN. A root init
    (boundary_init) mirrors the PUBLIC app source onto tmpfs /srv/tree (root-owned, world-readable --
    the agent is meant to read the source), then creates a SERVICE-owned, mode-0750 data dir
    /srv/data that the agent uid cannot even traverse.
  * The web app runs as the SERVICE uid. It is handed the flag in its environment (FLAG) plus
    DATA_DIR=/srv/data and PORT; on startup it STAGES ITS OWN SECRET under /srv/data (a file and/or a
    sqlite DB -- service-owned because the service uid creates it) and binds 127.0.0.1:PORT. The flag
    is then reachable only through the app's bug (IDOR / SQLi / path traversal).
  * Root SCRUBS FLAG from its environment before forking the agent, so no child but the service ever
    sees it.
  * The agent experiment runs as the AGENT uid (= host uid) from /work, PR_SET_NO_NEW_PRIVS set, and
    reaches the app only over the loopback HTTP tube. It cannot read /srv/data, traverse it, or chown
    its way in.

Recorded with sandbox_profile="container" plus profile_variant="web-service", so
solver/verifier.py's container-evidence rule applies unchanged (same as pwn-service).
"""
import json
import os
import subprocess
import uuid
from pathlib import Path

PROFILE = "web-service"
DEFAULT_PORT = 8080
_SOLVER = Path(__file__).resolve().parents[1] / "solver"
WEBCLIENT_SRC = _SOLVER / "web_client.py"
SESSION_SRC = _SOLVER / "session.py"        # web_client imports its pure helpers (safe_repr, budget, record)

# ---- in-container scripts (run as root, then dropped) ------------------------

BOUNDARY_INIT = r'''
import os, sys, shutil, socket, time, signal, ctypes
AGENT = int(os.environ["AGENT_UID"])
SERVICE = int(os.environ["SERVICE_UID"])
PORT = int(os.environ["PORT"])
APP_REL = os.environ.get("APP_REL", "app.py")
# Phase 21 additions (all default to the original Phase 19 synthetic behaviour when unset):
LAUNCH = os.environ.get("LAUNCH_KIND", "stdlib")     # stdlib | php | flask  (single service only)
SOURCE_MODE = os.environ.get("SOURCE_MODE", "public")  # public: tree world-readable (agent reads source,
#   synthetic). private: tree is SERVICE-owned 0750 (real black-box web: the agent never reads the
#   withheld server source, only talks HTTP).
FLAG_FILE = os.environ.get("FLAG_FILE", "")          # rel path in tree whose flag is staged service-owned
FLAG_TOKEN = os.environ.get("FLAG_TOKEN", "")        # placeholder in FLAG_FILE to replace with the real flag
#   (empty -> the whole file is overwritten with the flag)
DOCROOT = os.environ.get("DOCROOT", "")              # php -S doc root, rel to tree ("" -> tree root)
ROUTER = os.environ.get("ROUTER", "")                # optional php router script, rel to tree
# FLAG stays in the environment through the service fork (a synthetic app needs it to stage its own
# secret); it is scrubbed before the agent fork below.

def drop(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(38, 1, 0, 0, 0)          # PR_SET_NO_NEW_PRIVS

# root here has cap-drop ALL + only SETUID/SETGID/CHOWN -> no CAP_DAC_OVERRIDE, no CAP_FOWNER.
# So: chmod BEFORE chown (can't chmod a file once it is service-owned), and chown a directory only
# AFTER its children (a 0750 service-owned dir is no longer traversable by root -> CAP_DAC_OVERRIDE
# absent). The public (synthetic) source tree stays root-owned world-readable; a private (real) tree
# is locked to the service uid so the agent uid cannot read source it was never given.

os.makedirs("/srv", exist_ok=True)
os.chmod("/srv", 0o755)
# 1. mirror the app source onto writable tmpfs
shutil.copytree("/input/tree", "/srv/tree")
app_path = "/srv/tree/" + APP_REL
if LAUNCH in ("stdlib", "flask") and not os.path.exists(app_path):
    sys.stderr.write("boundary: app entrypoint missing: %s\n" % app_path); sys.exit(97)
# 1b. stage the real flag into its file (service-owned, never world-readable) so the agent can reach
#     it only through the app's bug, never with a direct open().
if FLAG_FILE:
    fp = "/srv/tree/" + FLAG_FILE
    flag = os.environ.get("FLAG", "")
    if FLAG_TOKEN:
        if not os.path.exists(fp):
            sys.stderr.write("boundary: flag file missing: %s\n" % fp); sys.exit(96)
        data = open(fp, "r", errors="replace").read()
        if FLAG_TOKEN not in data:
            sys.stderr.write("boundary: flag token not found in %s\n" % fp); sys.exit(95)
        open(fp, "w").write(data.replace(FLAG_TOKEN, flag))
    else:
        open(fp, "w").write(flag)
    os.chmod(fp, 0o640)                 # chmod before chown
    os.chown(fp, SERVICE, SERVICE)      # agent uid (other) -> cannot open it directly
# 1c. private tree: lock every path to the service uid, bottom-up (children before their dir).
if SOURCE_MODE == "private":
    for root, dirs, files in os.walk("/srv/tree", topdown=False):
        for n in files:
            p = os.path.join(root, n)
            stt = os.lstat(p)
            if os.path.islink(p) or stt.st_uid == SERVICE:
                continue                # already staged service-owned (e.g. the flag file)
            os.chmod(p, 0o750 if (stt.st_mode & 0o100) else 0o640)
            os.chown(p, SERVICE, SERVICE)
        if os.lstat(root).st_uid != SERVICE:
            os.chmod(root, 0o750)
            os.chown(root, SERVICE, SERVICE)
# 2. service-owned data dir the agent uid cannot traverse (0750). A synthetic app writes its own DB /
#    flag file here at startup; real challenges ignore it.
os.makedirs("/srv/data", exist_ok=True)
os.chmod("/srv/data", 0o750)            # chmod before chown (no CAP_FOWNER afterwards)
os.chown("/srv/data", SERVICE, SERVICE) # agent uid is neither owner nor group -> cannot read/traverse

# --- service as SERVICE uid: run the web app; it binds 127.0.0.1:PORT itself ---
svc = os.fork()
if svc == 0:
    drop(SERVICE)
    e = dict(os.environ)
    e["DATA_DIR"] = "/srv/data"; e["PORT"] = str(PORT)
    e.setdefault("HOME", "/tmp"); e.setdefault("USER", "ctf"); e.setdefault("LOGNAME", "ctf")
    if LAUNCH == "php":
        docroot = "/srv/tree/" + DOCROOT if DOCROOT else "/srv/tree"
        os.chdir(docroot)               # so the app's relative paths resolve against the doc root
        argv = ["php", "-d", "display_errors=0", "-S", "127.0.0.1:%d" % PORT, "-t", docroot]
        if ROUTER:
            argv.append("/srv/tree/" + ROUTER)
        os.execvpe("php", argv, e)
    elif LAUNCH == "flask":
        os.chdir("/srv/tree")
        os.execve(sys.executable, [sys.executable, "-I", app_path], e)  # app.run(host=127.0.0.1, port=PORT)
    else:  # stdlib (default): the Phase 19 synthetic path, unchanged
        os.chdir("/srv/tree")
        os.execve(sys.executable, [sys.executable, "-I", app_path], e)
    os._exit(127)

# wait until the app is listening (loopback TCP probe)
up = False
for _ in range(400):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=0.2); s.close(); up = True; break
    except OSError:
        time.sleep(0.05)
if not up:
    sys.stderr.write("boundary: app never bound 127.0.0.1:%d\n" % PORT)

os.environ.pop("FLAG", None)            # scrub: the agent child never sees the flag in its env

# --- agent experiment as AGENT uid ---
# The agent runs via a wrapper so IT (owner of /work) writes agent.rc: root has no CAP_DAC_OVERRIDE
# and cannot create files in the agent-owned /work.
ag = os.fork()
if ag == 0:
    drop(AGENT)
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

_BOOTSTRAP = "import sys as _s\n_s.path.insert(0, '/work/_lib')\ndel _s\n"

# Runs the agent's exp.py as the agent uid and records the real exit code to /work/agent.rc.
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


def run(run_dir, input_dir, flag, agent_code, *, app_rel="app.py", port=DEFAULT_PORT,
        exp_name="exploit", exp_id=None, image="ctfagent-web:0.1", wall_s=120,
        limits=None, agent_uid=None, service_uid=None, write_record=True,
        launch="stdlib", source_mode="public", flag_file="", flag_token="",
        docroot="", router=""):
    """Launch the web-service boundary and run `agent_code` (python) as the agent uid.

    `input_dir` is mounted read-only at /input; its `tree/` subdir is the app source and
    `tree/<app_rel>` is the server entrypoint (run as the service uid; it binds 127.0.0.1:PORT).
    Returns {exp_id, execution_status, stdout, stderr, rc, rec}.

    launch       : "stdlib" (default; `python3 -I tree/<app_rel>`, the Phase 19 synthetic path),
                   "php" (`php -S 127.0.0.1:PORT -t tree/<docroot> [tree/<router>]`), or
                   "flask" (`python3 -I tree/<app_rel>` where the app calls app.run). SINGLE SERVICE.
    source_mode  : "public" (tree stays root-owned world-readable -- synthetic; the agent reads the
                   source) or "private" (tree is SERVICE-owned 0750 -- real black-box web: the agent
                   never reads the withheld server source, only talks HTTP).
    flag_file    : rel path in tree whose flag is staged service-owned (not world-readable) so the
                   agent can only reach it through the app's bug. flag_token: placeholder in that file
                   to replace with the real flag ("" -> overwrite the whole file with the flag)."""
    run_dir = Path(run_dir)
    jail = run_dir / "work"
    artifacts = run_dir / "artifacts"
    (jail / "_lib").mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    agent_uid = os.getuid() if agent_uid is None else agent_uid
    service_uid = (1001 if agent_uid != 1001 else 1002) if service_uid is None else service_uid
    limits = limits or {"memory": "512m", "pids_limit": 256, "fsize_bytes": 67108864}

    (jail / "_lib" / "web_client.py").write_text(WEBCLIENT_SRC.read_text())
    (jail / "_lib" / "session.py").write_text(SESSION_SRC.read_text())
    (jail / "boundary_init.py").write_text(BOUNDARY_INIT)
    (jail / "agent_wrap.py").write_text(AGENT_WRAP)
    (jail / "exp.py").write_text(_BOOTSTRAP + agent_code)

    exp_id = exp_id or f"{Path(input_dir).name}-{exp_name}"
    name = f"ctfagent_websvc_{uuid.uuid4().hex[:12]}"
    # --read-only intentionally omitted (consistent with pwn-service): the service must create its DB /
    # flag file under /srv/data. Confidentiality rests on the uid+mode boundary (data dir is 0750
    # service-owned; agent uid cannot read it), proven by tests/test_web_boundary.py.
    argv = ["docker", "run", "--rm", "--name", name, "--network", "none",
            "--tmpfs", "/srv:rw,exec,mode=0755", "--tmpfs", "/tmp:rw",
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
             "-e", f"PORT={port}", "-e", f"APP_REL={app_rel}", "-e", f"FLAG={flag}",
             "-e", f"LAUNCH_KIND={launch}", "-e", f"SOURCE_MODE={source_mode}",
             "-e", f"FLAG_FILE={flag_file}", "-e", f"FLAG_TOKEN={flag_token}",
             "-e", f"DOCROOT={docroot}", "-e", f"ROUTER={router}",
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
