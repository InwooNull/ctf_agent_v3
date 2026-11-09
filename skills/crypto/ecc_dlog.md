# Elliptic curves & discrete logs (condition → attack → tool)

For these, `sage` is the right tool — it has curve arithmetic, group order, Pohlig–Hellman
and pairings built in. Invoke as `sage -c '…'` or run a script with `sage`. Read the curve
parameters (p, a, b) and the points exactly; identify which special case holds BEFORE
reaching for a generic DLOG.

## Singular curve (fast)
Condition: the curve is singular — discriminant Δ = −16(4a³+27b²) ≡ 0 (mod p). (A "curve"
with a cusp or node; often an accidentally/maliciously chosen a,b.)
Principle: a singular curve's smooth points form a group isomorphic to the additive group
(cusp) or the multiplicative group Fp*/a subgroup (node) — so the ECDLP collapses to an
easy additive or finite-field discrete log you can solve directly.
Failure signal: Δ ≠ 0 → not singular; use one of the below.

## Smooth order → Pohlig–Hellman
Condition: the order of the base point (or #E) factors into small primes.
Principle: solve the DLP modulo each small prime-power factor, CRT the results. Sage:
`E.order()` to factor, `P.discrete_log(Q)` already uses PH when it helps.
Failure signal: order has a large prime factor → PH won't finish; look for another special
case or give up on generic DLOG.

## Anomalous curve → Smart's attack
Condition: #E(Fp) = p (trace of Frobenius 1). 
Principle: a p-adic lift gives a group isomorphism to the additive group of Fp, turning
the ECDLP into a trivial division — linear time. Implement via the standard lift (sage).
Failure signal: #E(Fp) ≠ p → not anomalous.

## Small embedding degree → MOV / pairing
Condition: the embedding degree k is small (the subgroup order divides p^k − 1 for small
k; common on supersingular curves).
Principle: a pairing maps the ECDLP into the multiplicative group of F_{p^k}, where
index-calculus DLOG is feasible. Sage pairings + `discrete_log` in the field.
Failure signal: k large → the field F_{p^k} is astronomically big; abandon.

## Classic (non-EC) discrete log
Condition: y = g^x mod p. Small/smooth p−1 → Pohlig–Hellman (+ BSGS for the small parts).
Larger, smooth-ish → sage `discrete_log`. General safe-prime DLOG is hard — don't brute it.

## ECDSA nonce problems → lattice (HNP)
Condition: ECDSA signatures whose nonces k are biased (shared bits, short, or a repeated
k across two signatures).
- Repeated k (same r in two signatures): solve for k then the private key algebraically
  (two linear equations).
- Biased/partially-known k across many signatures: Hidden Number Problem → build a lattice
  and reduce. See `lattice.md` (fpylll) for the basis construction.
Failure signal: nonces look uniformly random and unique → no HNP handle.
