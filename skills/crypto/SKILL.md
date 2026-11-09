# Crypto cheat-sheet (C1 knowledge pack) — router

Knowledge only, in our own words: *which* attack fits *which* observation, the
condition that must hold for it to work, and *which tool* to reach for. It names no
challenge and contains no ready solution — you still derive and run the attack
in-container, with the same budget/isolation as C0 (`--network none`).

This is a capability-insurance layer for HARD problems: on easy challenges you will
(and should) just solve it directly. Load a detail file only when a signal matches —
never load everything.

## How to use (condition-first; do NOT blindly run tools)
1. `info` + inspect the artifacts first. Identify the scheme (RSA? a symmetric mode?
   ECC/DLOG? a PRNG? a lattice-shaped problem?) and read the GIVENS exactly: modulus
   `n`, exponent `e`, which values repeat, what is partially known, whether there is an
   interactive oracle.
2. Match the dominant signal below to a technique, then open ONE detail file for the
   condition + principle + a skeleton + the failure signal + which tool.
3. Confirm the technique's precondition BEFORE running anything (e.g. don't launch a
   full factorer if the real signal is "e=3 and m^e<n"). Running a heavy tool with the
   precondition unmet just burns budget.
4. If an attempt's failure signal fires, PIVOT to the alternative the detail file names
   rather than retrying the same thing.

## Technique router (signal → technique → file)
RSA (`rsa.md`):
- **primes look close** (n≈perfect square, or hint of |p−q| small) → **Fermat** factoring.
- **small e (e.g. 3) and the message is short** (m^e < n, or close) → **integer e-th root** (`iroot`); if m^e only slightly > n, try adding k·n.
- **same message to several recipients, same small e** → **Håstad broadcast** (CRT then e-th root).
- **same n, two different e with gcd(e1,e2)=1** → **common-modulus**.
- **d looks small / "fast decryption"** → **Wiener** (continued fractions); a bit larger d → **Boneh–Durfee** (lattice).
- **high/low bits of p known, or a stereotyped message** → **Coppersmith `small_roots`** (sage) → see `lattice.md`.
- **many keys share a prime** → **batch GCD**.
- **you've exhausted the structural attacks and just need n factored** → **RsaCtfTool** (`rsactftool`): it bundles many offline attacks; let it try. (Its `factordb` attack needs the Internet → unavailable here.)
Symmetric (`sym.md`):
- **ECB (identical plaintext blocks → identical ciphertext blocks), you can prepend input** → byte-at-a-time ECB decryption / cut-and-paste.
- **CBC and you can tamper ciphertext** → bit-flipping; **CBC + a padding-valid/invalid oracle** → padding oracle.
- **CTR/stream/OTP with a reused nonce or key** → keystream reuse (XOR ciphertexts, crib-drag).
- **XOR with a short/repeating key** → frequency / key-length analysis.
ECC & discrete log (`ecc_dlog.md`):
- **the curve is singular** (discriminant 0) → map to an easy group and solve the log.
- **curve order is smooth** → **Pohlig–Hellman**; **#E(Fp)=p (anomalous)** → **Smart's attack**; **small embedding degree** → **MOV/pairing**.
- **ECDSA with biased/repeated nonces** → Hidden Number Problem lattice → see `lattice.md`.
- tool for these: **sage**.
Lattices (`lattice.md`): knapsack/subset-sum, HNP/biased-nonce, truncated-LCG, Coppersmith, approximate-GCD → build a basis, reduce with **fpylll** LLL/BKZ (or sage), read the short vector.
PRNGs (`prng.md`): Mersenne Twister state recovery (624 outputs), LCG recovery, truncated-LCG (lattice), time/seed brute force, shuffle leakage.

## Which tool, and the offline caveat
- Our python + **pycryptodome/gmpy2/sympy/z3** cover most RSA-structural and symmetric work.
- **RsaCtfTool** (`rsactftool …`): many offline RSA attacks in one place — good last resort for "just factor n". Its online (factordb) attack will fail silently under `--network none`; that is expected, not a bug.
- **fpylll**: raw LLL/BKZ for any lattice-shaped problem.
- **sage** (`sage -c '…'` or a `.sage`/`.py` run with `sage`): Coppersmith `small_roots`, curve/DLOG machinery, when a pure-python route is too fiddly.
- **factordb**: NETWORK REQUIRED — not installed/usable here. Treat "look it up on factordb" as unavailable and fall back to Fermat/RsaCtfTool/your own factoring.

## Precondition-first, always
Every attack above has a precondition that is cheap to check and expensive to assume.
Check it first; if it does not hold, the attack cannot work no matter how long it runs.
