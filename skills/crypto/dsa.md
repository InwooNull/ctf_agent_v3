# (EC)DSA signature attacks (nonce is everything)

## When this fits
You are given DSA or ECDSA signatures `(r, s)` over known messages (or you can request
them), plus the public parameters. DSA/ECDSA security collapses entirely if the per-signature
nonce `k` is **reused, partially known, or biased** — that is almost always the intended
bug, not the discrete log itself. All arithmetic here is modular (order `n`); derive it
in-container with `gmpy2`/`pycryptodome`/`sympy` — no specialist tool needed for the
common cases.

Signatures: `r = (k·G).x mod n` (ECDSA) or `r = (g^k mod p) mod n` (DSA); `s = k⁻¹·(z + r·d)
mod n`, where `z` is the message hash (truncated to `n`'s bit length) and `d` is the secret
key. Recover `d` and you can forge any signature / it *is* the flag material.

## Reused nonce — same `r` in two signatures (the clean win)
If two signatures share the same `r`, they used the same `k`:
- `s1 = k⁻¹(z1 + r·d)`, `s2 = k⁻¹(z2 + r·d)` ⇒ `k = (z1 − z2) · (s1 − s2)⁻¹ mod n`.
- then `d = (s1·k − z1) · r⁻¹ mod n`.
Pure modular algebra — no lattice. Spotting the repeated `r` across a signature list is the
whole trick; scan for it first.

## Known / leaked nonce
If a single `k` is leaked (or guessable — a constant, a timestamp, `k = small`), then
`d = (s·k − z) · r⁻¹ mod n` directly from one signature. If nonces are **low-entropy**
(generated from a weak PRNG, sequential, or a tiny range) → brute `k`, checking each
candidate by recovering `d` and testing it against another signature. See `prng.md` if the
nonce comes from a recognizable PRNG.

## Biased / partially-known nonce — Hidden Number Problem
If you get **many** signatures whose nonces share known top/bottom bits (a short `k`, a
fixed MSB, `k < 2^b`), recovering `d` is an HNP solved by lattice reduction (build a lattice
from `s_i, r_i, z_i`, LLL-reduce, read `d` from a short vector). **fpylll/sage are not in
this image** — route the lattice construction through `lattice.md` (its fpylll-absent
fallback), or, for a handful of unknowns, try a `z3`/`sympy` model. This is the fallback
only; confirm there is a real bias first (a truly uniform `k` gives nothing).

## DSA-specific extras
- Same bug classes as ECDSA (DSA is the multiplicative-group analogue).
- If the group has smooth order or a small subgroup is reachable, the discrete-log side may
  be attackable → `ecc_dlog.md` / `prng.md`, but the nonce bug is usually the faster path.

## Failure signals → pivot
- No two signatures share `r`, and nonces look uniform/full-length → there is no nonce bug;
  re-read the challenge for a different weakness (bad parameter, reused `d` across schemes,
  a signing oracle you can abuse), or it may not be a DSA-nonce challenge at all.
- HNP lattice returns garbage → the assumed bias/bound is wrong; tighten or discard the
  "known bits" hypothesis rather than re-running.

## Not this
Plain discrete-log recovery (no signatures) → `ecc_dlog.md`. Lattice mechanics / LLL setup
→ `lattice.md`. RSA signatures → `rsa.md`.

## Verify
A recovered `d` must regenerate the public key (`Q = d·G`, or `y = g^d mod p`) and reproduce
the given signatures — check that in-container before trusting it, and never report a flag
derived from an unverified `d`.
