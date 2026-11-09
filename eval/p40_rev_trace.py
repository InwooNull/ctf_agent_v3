"""Phase 40 angr sanity trace: prove the reverse router ROUTES a VM/bytecode signal to
angr, and that angr REALLY runs in image ctfagent-rev:0.2 (--network none, non-root,
read-only root) and recovers the accepted input of a genuine fetch/decode/execute VM --
i.e. the conversion is real symbolic execution, not luck.

This is the independent "did angr actually solve a VM" check that backs the C1 conversion
table (eval/p40_rev_runner.py). It is synthetic (a VM crackme compiled in-container), so
it is pure analysis and cannot leak any holdout answer.

  python3 eval/p40_rev_trace.py        # -> store/p40_rev/trace.json

All built here; the solve runs in-container on image 0.2. No secrets/flags.
"""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack              # noqa: E402
from solver.rev_harness import RevHarness         # noqa: E402
from tools import sandbox                         # noqa: E402

IMAGE = "ctfagent-rev:0.2"
OUT = PROJECT_ROOT / "store" / "p40_rev"


def _harness(tag):
    d = Path(tempfile.mkdtemp())
    (d / "challenge.json").write_text(json.dumps({"id": tag, "category": "rev"}))
    store = Path(tempfile.mkdtemp())
    h = RevHarness(tag, d, store_root=store, image=IMAGE)
    # angr needs far more than the 256m default (same as the C1 measurement route's 2g).
    h.sandbox_config["container"]["limits"] = {
        "memory": "2g", "cpus": "1.0", "pids_limit": 256, "fsize_bytes": 67108864}
    return h


def _route(token):
    router = skill_pack.router_text("reverse")
    return [ln.strip() for ln in router.splitlines() if token in ln.lower()]


# A genuine register VM: a fetch/decode/execute loop over a bytecode `prog[]`. Opcodes:
#   0x01 LOADI r,idx  r[r]=input[idx]      0x02 XOR r,imm  r[r]^=imm
#   0x03 ADD   r,imm  r[r]+=imm            0x04 ROL r,imm  r[r]=rol(r[r],imm)
#   0x05 EQ    r,imm  ok &= (r[r]==imm)    0xff HALT
# The EQ immediates are computed in-container from a chosen printable plaintext so a unique
# solution exists; the plaintext is NOT written into the binary. angr executes the native
# interpreter symbolically and recovers the 8-byte input that reaches HALT with ok==1.
ANGR_CODE = r'''
import os, subprocess, textwrap
os.environ.setdefault("HOME", "/work")      # sitecustomize also sets HOME/TMPDIR + getpwuid shim
os.environ.setdefault("TMPDIR", "/work")

N = 8
PT = b"ANGRvm42"                             # the (printable) plaintext the VM accepts
XORK = [(0x5a + i) & 0xff for i in range(N)]
ADDK = [(i * 7 + 3) & 0xff for i in range(N)]
ROLK = [(i % 7) + 1 for i in range(N)]

def rol(v, r): v &= 0xff; return ((v << r) | (v >> (8 - r))) & 0xff
# expected register value after XOR,ADD,ROL for each byte -> the EQ immediate
EQ = []
for i in range(N):
    v = PT[i] ^ XORK[i]
    v = (v + ADDK[i]) & 0xff
    v = rol(v, ROLK[i])
    EQ.append(v)

# assemble the bytecode program: per byte -> LOADI, XOR, ADD, ROL, EQ ; then HALT
prog = []
for i in range(N):
    prog += [0x01, i, i, 0]          # LOADI r=i (use reg i mod 4 below), idx i
    prog += [0x02, i, XORK[i], 0]    # XOR
    prog += [0x03, i, ADDK[i], 0]    # ADD
    prog += [0x04, i, ROLK[i], 0]    # ROL
    prog += [0x05, i, EQ[i], 0]      # EQ
prog += [0xff, 0, 0, 0]              # HALT
prog_c = ",".join(str(b) for b in prog)

C_SRC = textwrap.dedent("""
#include <stdio.h>
#include <string.h>
static unsigned char rol(unsigned char v,int r){ return (unsigned char)((v<<r)|(v>>(8-r))); }
static const unsigned char prog[] = {%s};
int run(const unsigned char*in){
    unsigned char reg[8]={0}; int ok=1; size_t ip=0;
    while(ip < sizeof(prog)){
        unsigned char op=prog[ip], a=prog[ip+1], b=prog[ip+2];
        ip+=4;
        switch(op){
            case 0x01: reg[a&7]=in[b]; break;          /* LOADI r,idx (idx in b) */
            case 0x02: reg[a&7]^=b; break;             /* XOR */
            case 0x03: reg[a&7]=(unsigned char)(reg[a&7]+b); break;  /* ADD */
            case 0x04: reg[a&7]=rol(reg[a&7], b); break;             /* ROL */
            case 0x05: ok &= (reg[a&7]==b); break;     /* EQ */
            case 0xff: return ok;                      /* HALT */
            default: return 0;
        }
    }
    return ok;
}
int main(){
    unsigned char buf[32];
    if(!fgets((char*)buf,sizeof(buf),stdin)) return 1;
    if(run(buf)) puts("WIN"); else puts("NOPE");
    return 0;
}
""") % prog_c
open("/work/vm.c","w").write(C_SRC)
rc = subprocess.run(["gcc","-O0","-no-pie","-fno-stack-protector","/work/vm.c","-o","/work/vm"],
                    capture_output=True, text=True)
print("GCC_RC", rc.returncode, rc.stderr[:200])

# sanity: the native VM accepts PT (so a solution provably exists)
p = subprocess.run(["/work/vm"], input=PT, capture_output=True)
print("NATIVE_ACCEPTS_PT", b"WIN" in p.stdout)

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
flag = claripy.BVS("flag", 8*N)
st = proj.factory.full_init_state(stdin=flag)
for bb in flag.chop(8):                      # GUARD: bounded, printable input
    st.solver.add(bb >= 0x20, bb <= 0x7e)
sm = proj.factory.simulation_manager(st)
sm.explore(find=lambda s: b"WIN"  in s.posix.dumps(1),
           avoid=lambda s: b"NOPE" in s.posix.dumps(1))
print("ANGR_RAN 1")
if not sm.found:
    print("SOLVED False"); raise SystemExit(0)
recovered = sm.found[0].posix.dumps(0)[:N]
print("RECOVERED", recovered.hex())

# independently VERIFY by running the native VM on angr's recovered input
p = subprocess.run(["/work/vm"], input=recovered, capture_output=True)
ok = b"WIN" in p.stdout
print("BINARY_SAYS_WIN", ok)
print("SOLVED", ok)
'''


def trace():
    OUT.mkdir(parents=True, exist_ok=True)
    if not (sandbox.docker_available() and sandbox.image_available(IMAGE)):
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.rev02 first")

    h = _harness("p40_angr")
    o = h.run_experiment({"name": "angr_vm", "code": ANGR_CODE, "timeout": 300})
    out = o.stdout or ""
    step = {
        "signal": "a fetch/decode/execute loop over a bytecode program decides success (a VM)",
        "routed_to": _route("angr"),
        "tool": "angr (symbolic execution)",
        "exec": o.execution_status,
        "network_blocked": True,
        "compiled_in_container": "GCC_RC 0" in out,
        "native_accepts_plaintext": "NATIVE_ACCEPTS_PT True" in out,
        "tool_ran": "ANGR_RAN 1" in out,
        "recovered_input": next((ln.split()[1] for ln in out.splitlines()
                                 if ln.startswith("RECOVERED")), None),
        "binary_confirms_win": "BINARY_SAYS_WIN True" in out,
        "result_ok": "SOLVED True" in out,
    }
    report = {
        "image": IMAGE,
        "note": ("angr routing + sanity trace for the reverse lane. Proves the reverse router "
                 "points a VM/bytecode signal at angr, and that angr really runs in-container "
                 "(--network none, non-root, read-only root) and recovers the accepted input of "
                 "a genuine fetch/decode/execute VM -- i.e. a C1 angr conversion is real symbolic "
                 "execution, not luck. Backs the C0-vs-C1 conversion table."),
        "step": step,
        "routed": bool(step["routed_to"]),
        "tool_ran": step["tool_ran"],
        "result_ok": step["result_ok"],
        "stdout_tail": out[-800:],
    }
    (OUT / "trace.json").write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return report


if __name__ == "__main__":
    trace()
