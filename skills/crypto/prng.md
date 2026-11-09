# PRNG recovery (condition → principle → skeleton → failure → tool)

The question is always "how many consecutive outputs do I have, and are they truncated?"
Most of these are pure python; truncated cases go to a lattice (`lattice.md`, fpylll).

## Mersenne Twister (Python `random`, many languages' default)
Condition: ≥624 CONSECUTIVE 32-bit outputs observed (or enough raw bytes to assemble
them), no reseed in between.
Principle: MT19937's output is an invertible ("tempering") function of its state words.
Untemper each of 624 outputs to recover the full internal state, reload a generator with
that state, and you can reproduce all FUTURE (and, by inverting, past) outputs.
Skeleton: implement untemper (reverse the 4 temper steps: y^=y>>18; y^=(y<<15)&…; …),
collect 624 words, set them as the state, then predict.
Failure signal: fewer than 624 clean consecutive 32-bit outputs, or outputs are
`getrandbits(k<32)`/float/`randrange` (so bits are dropped) → you don't have full words;
you need to account for the dropped bits (harder) or gather more.
Note: if outputs are smaller than 32 bits each, it's a bit-reconstruction problem (solve
over GF(2) with the tempering+twist as linear relations, e.g. with z3 or a GF(2) solver).

## Linear congruential generator (LCG)
Condition: X_{n+1} = (a·X_n + c) mod m; you have consecutive full outputs.
Recover m: from several outputs form t_n = X_{n+1} − X_n; then m divides certain
determinants t_{n+2}t_n − t_{n+1}² → take gcd of a few of these to get m (up to small
cofactor). Recover a = (X2 − X1)·(X1 − X0)^{-1} mod m; c = X1 − a·X0 mod m.
Failure signal: recovered (a,c,m) don't predict the next output → not a plain LCG, or m
had a cofactor; refine with more samples.

## Truncated LCG (only high bits output)
Condition: LCG where each output is the top bits of the state (low bits hidden).
Principle: the hidden low bits are small unknowns in the linear recurrence → lattice
reduction recovers them (see `lattice.md`). Then proceed as full LCG.

## Seed brute force
Condition: generator seeded with something low-entropy — a timestamp, a PID, a small int.
Principle: enumerate the plausible seed space (e.g. a window of unix times around a known
event), regenerate, and match against observed output. Cheap when the window is small.
Failure signal: space too large to enumerate in budget → not the intended path.

## Shuffle / sampling leakage
Condition: you see the result of a shuffle or sampling that used the PRNG.
Principle: a Fisher–Yates shuffle leaks modular residues of successive outputs; enough of
them constrain the state the same way raw outputs do. Reconstruct the output stream from
the observed permutation/choices, then apply the relevant recovery above.
