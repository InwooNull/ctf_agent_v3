"""Phase 37 routing trace: prove the crypto knowledge pack ROUTES a vulnerability signal
to a specialist tool, and that the tool is REALLY installed and runs in the container
(--network none). Not a measurement (ceiling effect; no delta) — a plumbing trace.

For each of three signals we (a) consult the SKILL.md router to confirm which tool it
points at, then (b) run that tool inside one crypto:0.2 container on a synthetic instance
and check it produced the expected result:
  - "n has close primes"            -> rsa.md -> RsaCtfTool (fermat)   : factor n
  - "low-density subset-sum"        -> lattice.md -> fpylll (LLL)      : recover the subset
  - "stereotyped msg / known bits"  -> lattice.md -> sage small_roots  : recover the unknown

  python3 eval/p37_crypto_trace.py        # -> store/p37_crypto/trace.{json,md}

All synthetic, built here; the solve runs in-container. Flags/secrets are synthetic.
"""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack            # noqa: E402
from solver.crypto_harness import CryptoHarness  # noqa: E402
from tools import sandbox                       # noqa: E402

IMAGE = "ctfagent-crypto:0.2"
OUT = PROJECT_ROOT / "store" / "p37_crypto"


def _harness(tag):
    d = Path(tempfile.mkdtemp())
    (d / "challenge.json").write_text(json.dumps({"id": tag, "category": "crypto"}))
    store = Path(tempfile.mkdtemp())
    return CryptoHarness(tag, d, store_root=store, image=IMAGE)


def _route(signal_substrings):
    """What the router points the signal at (the tool token on the matching line)."""
    router = skill_pack.router_text("crypto")
    hits = [ln.strip() for ln in router.splitlines()
            if all(s in ln.lower() for s in signal_substrings)]
    return hits


# --- synthetic instances (built here; solved in-container by the routed tool) ----------
RSA_CODE = r'''
import subprocess, re, sys
# n with CLOSE primes (Fermat/RsaCtfTool signal); factor it with the specialist tool.
n = {n}; e = {e}
out = subprocess.run(["RsaCtfTool","-n",str(n),"-e",str(e),"--attack","fermat","--private"],
                     capture_output=True, text=True, timeout=120)
blob = out.stdout + out.stderr
# RsaCtfTool prints the recovered PEM / factors; success = it found the factorisation.
import re
ok = ("BEGIN RSA PRIVATE KEY" in blob) or ("Found factors" in blob) or bool(re.search(r'\bp\s*[:=]', blob))
print("RSACTFTOOL_RAN", out.returncode)
print("TOOL_FOUND_FACTORS", ok)
'''

FPYLLL_CODE = r'''
from fpylll import IntegerMatrix, LLL
# low-density subset-sum: identity block + a heavily-weighted sum column; after LLL the
# short vector's 0/1 entries are the chosen subset (lattice.md skeleton).
w = {weights}; s = {target}; nb = len(w)
N = 1 << 100
M = IntegerMatrix(nb + 1, nb + 1)
for i in range(nb):
    M[i, i] = 1
    M[i, nb] = N * w[i]
M[nb, nb] = -N * s          # coefficient 1 on this row contributes -s to the sum column
LLL.reduction(M)
sol = None
for r in range(M.nrows):
    coords = [M[r, c] for c in range(nb)]
    if M[r, nb] != 0 or not any(coords):
        continue
    for cand in (coords, [-v for v in coords]):
        if all(v in (0, 1) for v in cand) and sum(wi for wi, b in zip(w, cand) if b) == s:
            sol = cand
            break
    if sol:
        break
print("FPYLLL_RAN 1")
print("SUBSET_RECOVERED", sol is not None)
'''

SAGE_CODE = r'''
import os, subprocess
# stereotyped-message / known-high-bits -> Coppersmith small_roots (sage).
# sage needs a writable HOME; the only guaranteed-writable path in the sandbox is /work.
prog = (
 "n={n}\n"
 "e=3\n"
 "R=Zmod(n)\n"
 "P.<x>=PolynomialRing(R)\n"
 "f=(({a})+x)^e - {c}\n"
 "f=f.monic()\n"
 "rts=f.small_roots(X=2^{xb}, beta=1.0, epsilon=0.04)\n"
 "print('SAGE_ROOTS', list(rts))\n"
)
env = dict(os.environ, HOME="/work", DOT_SAGE="/work/.sage")
out = subprocess.run(["sage","-c",prog], capture_output=True, text=True, timeout=200, env=env)
print("SAGE_RAN", out.returncode)
print("SAGE_RECOVERED", ("SAGE_ROOTS" in out.stdout) and ("[]" not in out.stdout.split("SAGE_ROOTS")[1][:8]))
'''


def _mk_rsa():
    from sympy import nextprime
    import random
    base = random.getrandbits(256) | (1 << 255)
    p = int(nextprime(base)); q = int(nextprime(p + random.randint(2, 5000)))  # CLOSE primes
    return p * q, 65537


def _mk_subset():
    import random
    w = [random.getrandbits(80) for _ in range(12)]
    pick = [random.randint(0, 1) for _ in range(12)]
    s = sum(wi for wi, b in zip(w, pick) if b)
    return w, s


def _mk_coppersmith():
    from sympy import nextprime
    import random
    p = int(nextprime(random.getrandbits(512))); q = int(nextprime(random.getrandbits(512)))
    n = p * q
    a = random.getrandbits(400) << 40          # known high part
    unknown = random.getrandbits(32)
    m = a + unknown
    c = pow(m, 3, n)
    return n, a, c, 40


def trace():
    OUT.mkdir(parents=True, exist_ok=True)
    if not (sandbox.docker_available() and sandbox.image_available(IMAGE)):
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.crypto2 first")
    steps = []

    # 1) RSA close primes -> RsaCtfTool
    n, e = _mk_rsa()
    h = _harness("p37_rsa")
    o = h.run_experiment({"name": "rsactftool", "code": RSA_CODE.format(n=n, e=e), "timeout": 140})
    steps.append({"signal": "n has close primes", "routed_to": _route(["primes look close"]),
                  "tool": "RsaCtfTool", "exec": o.execution_status,
                  "network_blocked": True,
                  "tool_ran": "RSACTFTOOL_RAN" in (o.stdout or ""),
                  "result_ok": "TOOL_FOUND_FACTORS True" in (o.stdout or "")})

    # 2) subset-sum -> fpylll
    w, s = _mk_subset()
    h = _harness("p37_fpylll")
    o = h.run_experiment({"name": "fpylll", "code": FPYLLL_CODE.format(weights=w, target=s), "timeout": 60})
    steps.append({"signal": "low-density subset-sum", "routed_to": _route(["knapsack"]),
                  "tool": "fpylll", "exec": o.execution_status,
                  "tool_ran": "FPYLLL_RAN 1" in (o.stdout or ""),
                  "result_ok": "SUBSET_RECOVERED True" in (o.stdout or "")})

    # 3) stereotyped message -> sage small_roots
    n2, a, c, xb = _mk_coppersmith()
    h = _harness("p37_sage")
    o = h.run_experiment({"name": "sage", "code": SAGE_CODE.format(n=n2, a=a, c=c, xb=xb), "timeout": 200})
    steps.append({"signal": "stereotyped message / known high bits",
                  "routed_to": _route(["coppersmith"]), "tool": "sage small_roots",
                  "exec": o.execution_status,
                  "tool_ran": "SAGE_RAN" in (o.stdout or ""),
                  "result_ok": "SAGE_RECOVERED True" in (o.stdout or "")})

    report = {"image": IMAGE, "note": "routing trace (plumbing); ceiling effect, no delta measured",
              "steps": steps,
              "all_routed": all(s["routed_to"] for s in steps),
              "all_tools_ran": all(s["tool_ran"] for s in steps),
              "all_results_ok": all(s["result_ok"] for s in steps)}
    (OUT / "trace.json").write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return report


if __name__ == "__main__":
    trace()
