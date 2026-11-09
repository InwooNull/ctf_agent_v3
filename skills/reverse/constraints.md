# Constraint / crackme

## When this fits
The program reads an input and runs it through a series of checks — per-byte comparisons,
`input[i] ^ k[i] == c[i]`, a sum/product that must equal a constant, a small system of
equations, a checksum — and prints success only if all pass. No VM, no heavy obfuscation;
the check is readable (or becomes readable after de-flattening / decoding).

## Procedure (our words)
1. **Collect every constraint.** Read the check and write each one as an equation over
   the input bytes: `x[0] ^ 0x41 == 0x13`, `x[3] + x[4] == 0xa0`, `sum(x) == 0x...`, etc.
   Note the input length and charset the program enforces.
2. **Invert or solve.**
   - **Direct inversion** — if each byte is independently recoverable (xor/add/sub/rotate
     against a known constant), just invert it. This is faster than loading angr; do it
     first when the checks are per-byte and independent.
   - **z3 by hand** — when bytes are coupled (sums, products, a permutation, a matrix),
     model it in z3 and solve. `z3-solver` is in the image.
   - **angr** — when extracting the constants by hand is error-prone or the control flow
     hides them, let angr do it (below).
3. **Reconstruct the flag** from the solved bytes, and **verify in-container** by feeding
   it back to the binary — never submit an un-run solution.

## z3 by hand (coupled constraints)
```
from z3 import *
n = 20
x = [BitVec(f'x{i}', 8) for i in range(n)]
s = Solver()
for xi in x: s.add(xi >= 0x20, xi <= 0x7e)   # charset bound
# ... add one s.add(...) per recovered constraint ...
assert s.check() == sat
m = s.model()
print(bytes(m[xi].as_long() for xi in x))
```

## angr (let it extract + solve)
```
import angr, claripy   # import angr; claripy = angr.claripy on this image
proj = angr.Project(path, auto_load_libs=False)
flag = claripy.BVS('flag', 8*n)
st = proj.factory.full_init_state(stdin=flag)
for i in range(n):
    st.solver.add(flag.get_byte(i) >= 0x20, flag.get_byte(i) <= 0x7e)
sm = proj.factory.simulation_manager(st)
sm.explore(find=WIN_ADDR, avoid=FAIL_ADDR)
print(sm.found[0].posix.dumps(0))
```
For a pure per-byte crackme this is overkill — invert by hand. Use angr when the checks
are numerous or buried.

## Failure signals → what to do
- z3 `unsat` → a constraint is transcribed wrong (sign, endianness, off-by-one) or you
  missed a charset bound; re-derive the suspect equation from the disassembly.
- Solved input rejected by the binary → there is an extra check you didn't model (length,
  a final checksum, a trailing byte); re-read to the very end of the success path.
- Many solutions / ambiguous → add the charset and length bounds; the flag is usually the
  unique printable solution.
