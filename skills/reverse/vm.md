# VM / bytecode interpreter

## When this fits
A dispatch loop that reads a byte (or word) from a buffer, uses it to pick an operation
(an opcode `switch`, a jump table, or an array of handler pointers), does something to a
register/stack array, advances a program counter, and repeats. The "program" is a blob
in `.data`/`.rodata` or supplied as input. The flag check runs *inside* the VM, not in
native code.

## Procedure (our words)
1. **Find the three parts.** (a) the dispatch loop (the `while` that reads `code[pc]`),
   (b) the opcode→handler mapping (switch cases / pointer table — list every opcode and
   what it does to the VM state), (c) the VM state (registers/stack/memory arrays, the
   PC, flags). `objdump -d` + patience; a jump table shows up as an indirect call/jmp
   through a `.rodata` array.
2. **Reconstruct the ISA.** Write down each opcode: operands, effect, how it changes PC.
   Watch for: variable-length instructions, a bytecode that is itself xor/offset-encoded
   before execution, and opcodes that read the *input* vs the *program*.
3. **Find the win condition.** What VM state means "accepted"? Usually a final compare
   of a VM register/array against constants, or reaching a HALT with a flag set.
4. **Recover the input.** Two routes:
   - **Manual emulator** — reimplement the ISA in Python, run the embedded program, and
     either read what it checks and invert it, or brute the input if the space is small.
     Best when the ISA is small/clean and you understand the check.
   - **angr** — let symbolic execution find the accepted input *without* you rebuilding
     the ISA, by treating the native interpreter as the thing to execute symbolically.
     Best when the ISA is large or ugly. See below.

## angr on a VM (guarded)
The native binary *is* the interpreter; angr executes it, so you do not have to write the
emulator — you only point it at success/failure.
```
import angr, claripy  # (on this image: import angr; claripy = angr.claripy)
proj = angr.Project(path, auto_load_libs=False)
n = 32                                   # guess/limit the flag length
inp = claripy.BVS('inp', 8*n)
st = proj.factory.full_init_state(stdin=inp)   # or args=[...] / a fixed buffer
for i in range(n):                        # BOUND each byte: printable
    b = inp.get_byte(i)
    st.solver.add(b >= 0x20, b <= 0x7e)
sm = proj.factory.simulation_manager(st)
sm.use_technique(angr.exploration_techniques.Veritesting())   # helps VM/flattening
sm.explore(find=WIN_ADDR, avoid=[FAIL_ADDR, EXIT_ADDR], n=200)  # cap steps
if sm.found:
    print(sm.found[0].posix.dumps(0))     # the stdin that reaches WIN
```
- `WIN_ADDR` / `FAIL_ADDR`: read them off `objdump`/gdb (the `puts("correct")` block and
  the reject/`exit` block). Getting these right is 90% of the work.
- If it explodes anyway: shrink `n`, tighten the byte constraints to the real charset,
  `hook` the interpreter's I/O, or fall back to the manual emulator for the hot loop.

## Failure signals → what to do
- angr hangs / RAM climbs to the cap → state explosion: add `avoid`, add Veritesting,
  cut `n`, bound bytes harder, or go manual.
- `sm.found` empty though it finished → WIN_ADDR wrong, or the input doesn't reach it on
  stdin (try `args`/a memory buffer; re-read how the program ingests input).
- The embedded program is encoded → decode it first (xor/rotate pass) before emulating.

## Not this
If there is no interpreter loop — just straight-line native checks on the input — this is
a **constraint/crackme** (`constraints.md`), not a VM.
