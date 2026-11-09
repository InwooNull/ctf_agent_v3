"""Scripted (non-LLM) driver that proves the crypto pipeline end to end.

For each dev challenge it hardcodes the correct solve steps, runs them through
the harness (i.e. inside the container), reads the flag back *from the container
stdout*, and reports it as a candidate with the producing experiment as evidence.
No LLM, no reasoning — just a deterministic driver for the plumbing. Claude's own
reasoning comes in Phase 4.
"""
import re

from solver.crypto_harness import CryptoHarness

FLAG_RE = re.compile(r"FLAG\{[^}]*\}")

# challenge_id -> (hypothesis, solve script run inside the container)
SOLVERS = {
    "ch1_encoding": (
        "cipher.txt is base64( hex( base64( flag ) ) )",
        r"""
import base64, binascii
data = open('/input/cipher.txt', 'rb').read().strip()
step1 = base64.b64decode(data)       # -> ascii hex
step2 = binascii.unhexlify(step1)    # -> inner base64 ascii
flag = base64.b64decode(step2).decode()
print(flag)
""",
    ),
    "ch2_smallrsa": (
        "n is a product of two small primes; factor with sympy then decrypt",
        r"""
import json, sympy
p = json.load(open('/input/params.json'))
n, e, c = p['n'], p['e'], p['c']
factors = list(sympy.factorint(n))
P, Q = factors[0], factors[1]
phi = (P - 1) * (Q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
print(flag)
""",
    ),
}


def extract_flag(text):
    match = FLAG_RE.search(text or "")
    return match.group(0) if match else None


def solve(challenge_dir, run_id, store_root=None, image=None):
    """Drive one challenge through the harness. Returns (harness, outcome, reported_flag)."""
    kwargs = {"store_root": store_root}
    if image is not None:
        kwargs["image"] = image
    h = CryptoHarness(run_id, challenge_dir, **kwargs)
    statement, code = SOLVERS[h.challenge_id]
    h.record_hypothesis(statement, priority_band="high")
    outcome = h.run_experiment({"name": "solve", "code": code, "timeout": 60})
    flag = extract_flag(outcome.stdout)
    if flag:
        h.report_candidate(flag, evidence_refs=[outcome.exp_id])
    return h, outcome, flag
