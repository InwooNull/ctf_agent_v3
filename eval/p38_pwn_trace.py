"""Phase 38 angr routing trace: prove the pwn knowledge pack ROUTES a VM/logic-check
signal to angr, and that angr is REALLY installed and runs in the container
(--network none) and recovers the correct input. This is NOT a holdout measurement —
the heap_hard pwn subset is not angr-shaped, so angr has no real-holdout target this
phase; this trace is its capability-insurance sanity check (the pwndbg arm IS measured
on the real heap_hard subset, separately, by the p38 C0-vs-C1 runner).

Mirror of eval/p37_crypto_trace.py (per-tool trace), one arm:
  - "input -> state / VM or logic check" -> SKILL.md tool router -> angr symbolic :
    compile a tiny logic-check crackme in-container, let angr find the WIN input,
    confirm the recovered input actually satisfies the check.

  python3 eval/p38_pwn_trace.py        # -> store/p38_pwn/trace.json

All synthetic, built here; the solve runs in-container on image 0.3. No secrets/flags.
"""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack              # noqa: E402
from solver.crypto_harness import CryptoHarness   # noqa: E402
from tools import sandbox                         # noqa: E402

IMAGE = "ctfagent-pwn:0.3"
OUT = PROJECT_ROOT / "store" / "p38_pwn"


def _harness(tag):
    d = Path(tempfile.mkdtemp())
    (d / "challenge.json").write_text(json.dumps({"id": tag, "category": "pwn"}))
    store = Path(tempfile.mkdtemp())
    h = CryptoHarness(tag, d, store_root=store, image=IMAGE)
    # angr (like torch in mlsec) needs far more than the 256m crypto default.
    h.sandbox_config["container"]["limits"] = {
        "memory": "2g", "cpus": "1.0", "pids_limit": 256, "fsize_bytes": 67108864}
    return h


def _route(token):
    """Router lines that name the tool for this signal."""
    router = skill_pack.router_text("pwn")
    return [ln.strip() for ln in router.splitlines() if token in ln.lower()]


# A tiny logic-check crackme (input -> state): per-index mix of xor+add+rotate compared
# against a baked constant. Not a heap/ROP problem -> exactly angr's domain. Compiled and
# solved entirely in-container; angr recovers the 8-byte WIN input symbolically.
ANGR_CODE = r'''
import os, subprocess, textwrap, pwd
os.makedirs("/work/.angr_home", exist_ok=True)
os.environ["HOME"] = "/work/.angr_home"
os.environ.setdefault("USER", "agent"); os.environ.setdefault("LOGNAME", "agent")
# This plain container runs as the host uid, which has no /etc/passwd entry; angr's
# import chain calls pwd.getpwuid(uid). Shim it so the import survives. (The real C1
# measurement runs under the pwn-service boundary, whose ensure_etc_users() already
# writes a passwd entry for the agent uid -- Phase 33 -- so this shim is trace-only.)
_orig_getpwuid = pwd.getpwuid
def _safe_getpwuid(uid):
    try:
        return _orig_getpwuid(uid)
    except KeyError:
        return pwd.struct_passwd(("agent", "x", uid, uid, "agent", "/work/.angr_home", "/bin/sh"))
pwd.getpwuid = _safe_getpwuid

C_SRC = textwrap.dedent("""
#include <stdio.h>
#include <string.h>
static unsigned char rol(unsigned char v, int r){ return (unsigned char)((v<<r)|(v>>(8-r))); }
int check(const unsigned char*s){
    unsigned char t[8];
    for(int i=0;i<8;i++){
        unsigned char v = s[i];
        v ^= (unsigned char)(0x5a + i);
        v = (unsigned char)(v + (i*7 + 3));
        v = rol(v, (i%7)+1);
        t[i] = v;
    }
    /* K derived from a printable 8-byte plaintext so a (unique) solution exists. */
    static const unsigned char K[8] = {0x3c,0x7c,0x61,0x72,0xa9,0x93,0x9d,0xe8};
    return memcmp(t, K, 8)==0;
}
int main(){
    unsigned char buf[16];
    if(!fgets((char*)buf,16,stdin)) return 1;
    if(check(buf)) puts("WIN"); else puts("NOPE");
    return 0;
}
""")
open("/work/vm.c","w").write(C_SRC)
rc = subprocess.run(["gcc","-O0","-no-pie","-fno-stack-protector","/work/vm.c","-o","/work/vm"],
                    capture_output=True, text=True)
print("GCC_RC", rc.returncode, rc.stderr[:200])

try:
    import angr
except Exception as e:
    import traceback; traceback.print_exc()
    print("ANGR_IMPORT_FAILED", repr(e)); raise SystemExit(0)
claripy = angr.claripy
import logging
for n in ("angr","cle","pyvex","claripy"):
    logging.getLogger(n).setLevel("ERROR")

proj = angr.Project("/work/vm", auto_load_libs=False)
flag = claripy.BVS("flag", 8*8)
st = proj.factory.full_init_state(stdin=flag)
for b in flag.chop(8):                  # bounded search space: 8 printable bytes
    st.solver.add(b >= 0x20, b <= 0x7e)
sm = proj.factory.simulation_manager(st)
sm.explore(find=lambda s: b"WIN"  in s.posix.dumps(1),
           avoid=lambda s: b"NOPE" in s.posix.dumps(1))
print("ANGR_RAN 1")
if not sm.found:
    print("SOLVED False"); raise SystemExit(0)
recovered = sm.found[0].posix.dumps(0)[:8]
print("RECOVERED", recovered.hex())

# Independently VERIFY the recovered input really passes check() by running the binary.
p = subprocess.run(["/work/vm"], input=recovered, capture_output=True)
ok = b"WIN" in p.stdout
print("BINARY_SAYS_WIN", ok)
print("SOLVED", ok)
'''


def trace():
    OUT.mkdir(parents=True, exist_ok=True)
    if not (sandbox.docker_available() and sandbox.image_available(IMAGE)):
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.pwn03 first")

    h = _harness("p38_angr")
    o = h.run_experiment({"name": "angr_vm", "code": ANGR_CODE, "timeout": 240})
    out = o.stdout or ""
    step = {
        "signal": "input -> state mapping is complex / a VM or logic check decides success",
        "routed_to": _route("angr"),
        "tool": "angr (symbolic execution)",
        "exec": o.execution_status,
        "network_blocked": True,
        "compiled_in_container": "GCC_RC 0" in out,
        "tool_ran": "ANGR_RAN 1" in out,
        "recovered_input": next((ln.split()[1] for ln in out.splitlines()
                                 if ln.startswith("RECOVERED")), None),
        "binary_confirms_win": "BINARY_SAYS_WIN True" in out,
        "result_ok": "SOLVED True" in out,
    }
    report = {
        "image": IMAGE,
        "note": ("angr routing+sanity trace (capability insurance). The heap_hard pwn subset "
                 "is NOT angr-shaped, so angr has no real-holdout target this phase; pwndbg is "
                 "the measured tool (see p38 C0-vs-C1 conversion table). This trace only proves "
                 "the router points VM/logic signals at angr and that angr really runs "
                 "in-container (--network none) and recovers a correct input."),
        "step": step,
        "routed": bool(step["routed_to"]),
        "tool_ran": step["tool_ran"],
        "result_ok": step["result_ok"],
    }
    (OUT / "trace.json").write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return report


if __name__ == "__main__":
    trace()
