# Lattice attacks (condition → basis → read-off → failure → tool)

When a problem reduces to "find a small/short integer combination," a lattice + LLL/BKZ is
the hammer. Tool: **fpylll** (`from fpylll import IntegerMatrix, LLL, BKZ`) for raw
reduction; **sage** for Coppersmith `small_roots` convenience. The craft is BASIS DESIGN
and SCALING — a wrong weight makes the target vector non-shortest and LLL returns garbage.

General recipe:
1. Express the secret as a short vector in a lattice you can write down from public data.
2. Scale rows (multiply by constants) so the target really is the shortest/closest vector
   and the "junk" coordinates are heavily penalized.
3. Reduce (`LLL.reduction(M)` or BKZ for harder instances), then scan the reduced rows for
   the one matching your structure (right sign, expected known coordinate) and read the
   secret off.
Failure signal: no reduced row has the expected form / known coordinate → rescale (the
balance between the "value" column and the "coefficient" columns is wrong), or you need
more samples (equations).

## Subset-sum / knapsack (low density)
Condition: s = Σ b_i·x_i with x_i ∈ {0,1} and density n/log2(max b_i) < ~0.94.
Basis: identity block on the x_i plus a last column [b_i; −s] with a large weight.
Read-off: the short vector's 0/1 entries are the x_i.

## Hidden Number Problem / biased ECDSA nonces
Condition: many relations t_i·α ≈ u_i (mod q) where α is the secret and the error (the
unknown nonce bits) is small relative to q.
Basis: diagonal q's, the t_i row, and a row carrying the u_i, scaled by 2^(bit-leak) so the
small-error solution is shortest (standard HNP embedding).
Read-off: recover α from the short vector; verify against a known signature.
Failure signal: too few relations or too little bias → CVP target isn't short enough.

## LCG / truncated LCG recovery
Condition: outputs of X_{n+1} = a·X_n + c mod m, possibly with low bits truncated.
Full outputs: recover m from gcd of determinants of consecutive differences, then a, c by
algebra (see `prng.md`). Truncated: the unknown low bits form a short vector — build a
lattice over the recurrence and reduce.
Failure signal: recovered a,c don't reproduce the next output → wrong m or too few samples.

## Coppersmith small_roots
Condition: a small root of a univariate (or carefully-built multivariate) polynomial mod n
— stereotyped RSA message, known high bits of a factor, Boneh–Durfee.
Sage: `R.<x>=PolynomialRing(Zmod(n)); (f).small_roots(X=2^k, beta=b)`. Pick X = bound on
the unknown and beta = log_n of the factor you're targeting (beta=1 for mod-n messages,
~0.5 for a factor). fpylll route: build the Coppersmith/Howgrave-Graham basis by hand and
LLL-reduce if sage is unavailable.
Failure signal: empty root list → the unknown exceeds the bound (X/beta too optimistic);
you need more known bits or a better polynomial.

## Approximate GCD
Condition: several x_i = q_i·p + r_i with small r_i (p the hidden shared ~divisor).
Basis: the standard ACD lattice ([2^ρ, x1, x2, …; 0, −x0, …]); reduce and read p.
