# RSA attacks (condition → principle → skeleton → failure signal → tool)

Read the givens exactly first: `n`, `e`, `c`, and anything "extra" (a second ciphertext,
a second modulus, partial bits, a hint about d or the primes). The right attack is
almost always dictated by which extra you were given. Derive numbers in-container; never
reuse a value from memory.

## Fermat — primes are close
Condition: |p−q| small (hint: "generated p then nextprime", n close to a perfect square).
Principle: n = a² − b² = (a−b)(a+b); start a = ⌈√n⌉ and increment until a²−n is a square.
Skeleton: `a=isqrt(n); while not is_square(a*a-n): a+=1`; then p=a−b, q=a+b.
Failure signal: a runs far past √n with no square → primes aren't close; stop, pivot.
Tool: gmpy2.isqrt; or `rsactftool --attack fermat`.

## Small e, short message — integer e-th root
Condition: e small (often 3) AND m^e < n (or only slightly above). Then c = m^e exactly
(no modular wrap), so m = c^(1/e) over the integers.
Skeleton: `m,exact = gmpy2.iroot(c, e)`; if not exact, try `gmpy2.iroot(c + k*n, e)` for
small k (handles a small wrap). 
Failure signal: no exact root for any small k → message isn't short; consider Håstad or
Coppersmith (stereotyped message).

## Håstad broadcast — same m, same small e, many n
Condition: identical m sent with the same e=k to k recipients (n1..nk coprime).
Principle: CRT the ciphertexts to get m^k mod ∏n, which equals m^k over the integers
(since m^k < ∏n), then take the integer k-th root.
Failure signal: root not exact → messages weren't identical, or padding differs.

## Common modulus — same n, two e
Condition: same n, two ciphertexts of the same m under e1,e2 with gcd(e1,e2)=1.
Principle: find a·e1 + b·e2 = 1 (extended gcd); then c1^a · c2^b ≡ m (mod n) (use modular
inverse for the negative exponent).
Failure signal: gcd(e1,e2)≠1 → doesn't apply directly.

## Wiener / Boneh–Durfee — small private exponent
Condition: d small. Wiener works for d < n^0.25; Boneh–Durfee extends to ~n^0.292.
Wiener principle: e/n ≈ e/φ; a convergent of the continued fraction of e/n reveals k/d,
from which d (and φ, then the factors) follow. Verify a candidate d by checking a known
(m^e)^d ≡ m.
Boneh–Durfee: a Coppersmith-style lattice on the equation — use sage (`small_roots`),
see `lattice.md`.
Failure signal: no convergent yields a consistent d → d not small enough for Wiener →
try Boneh–Durfee, else abandon the "small d" hypothesis.
Tool: pure python (continued fractions) for Wiener; sage for Boneh–Durfee; `rsactftool
--attack wiener,boneh_durfee`.

## Partial knowledge — Coppersmith
Condition: you know the high (or low) bits of p, OR the message is stereotyped (known
prefix/suffix, few unknown bytes). 
Principle: a small modular root of a well-chosen polynomial is recoverable by lattice
reduction when the unknown is small enough (≈ known half of p for factoring; unknown <
n^(1/e) for a stereotyped message). 
Tool: sage `PolynomialRing(Zmod(n)); f.small_roots(X=…, beta=…)`. See `lattice.md` for the
fpylll route if sage is unavailable. Failure signal: no root in bound → unknown part too
large; you need more known bits.

## Shared factor across keys — batch GCD
Condition: several public n_i from the same (bad) generator. 
Principle: gcd(n_i, n_j) may reveal a shared prime. Pairwise gcd for a few keys, or a
product-tree batch gcd for many.
Failure signal: all gcds are 1 → no shared factor.

## Last resort — RsaCtfTool
When the structural signals above don't match and you just need n factored, run
`rsactftool --publickey key.pub --private` or pass `-n … -e … --uncipher c`. It tries a
large bank of OFFLINE attacks (fermat, wiener, small_q, pollard p−1, williams p+1,
ecm for small factors, etc.). Give it the parameters and let it run within budget.
Caveat: its `factordb` attack needs the Internet and will fail here — ignore that line.
It is a convenience over the Internet's known factorizations, not a magic factorizer:
a hard RSA-2048 with no structure stays hard.
