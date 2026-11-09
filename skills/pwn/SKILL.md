# Pwn cheat-sheet (C1 knowledge pack) — router

Knowledge only, in our own words: *which* technique fits *which* observation, and
where the version-specific traps are. It names no challenge and contains no ready
exploit — you still derive the exploit, in-container, with the same tools/budget as C0.
Load a detail file only when the signal below matches.

## How to use
1. `info` first: read `checksec` (RELRO/NX/PIE/Canary), the libc version, and what the
   program lets you do (alloc/free/edit/show, read/write primitives, fixed sizes?).
2. Match the dominant signal to a technique, then open the detail file for the recipe
   and the glibc-version caveats. Confirm every address/offset in-container before use.
3. If a leak is missing, solving the **leak** is usually the real first subproblem.

## Technique router (signal → technique → file)
- **heap alloc/free menu, UAF or double-free** → tcache poisoning / fastbin dup /
  tcache-key & safe-linking caveats → `heap.md`
- **overflow into a freed/large chunk, want an arbitrary chunk** → unsorted-bin leak,
  House of Force / House of Apple(2.35+) → `heap.md`
- **you control a FILE pointer or need RCE from a write primitive on 2.35+** →
  FSOP / `_IO_FILE` (House of Apple 2) → `heap.md`
- **no address leak yet** → leak strategy (unsorted-bin main_arena, GOT via format
  string, partial-overwrite under PIE/ASLR) → `leaks.md`
- **stack overflow, NX on, no win()** → ROP: ret2libc, ret2csu, SROP, stack pivot →
  `rop.md`
- **anything behaves differently than the recipe says** → it is almost always the
  libc version: check `glibc_versions.md` before burning budget.

## The version question comes first
tcache (2.26+), tcache double-free key (2.29+), safe-linking pointer mangling
(2.32+), and the `_IO_FILE` vtable-check changes (2.24 / 2.35) each *silently* break
a recipe written for another version. Read the libc version off `info`/`file`/the
shipped `libc.so.6` and branch on it — see `glibc_versions.md`. Mismatched loader/libc
in the materials is a deployment problem, not a technique to try.

## Tool router (signal → specialist tool)  [image ctfagent-pwn:0.3]
Knowledge above tells you *which technique*; this tells you *which tool* to reach
for, and when NOT to. Tools do not replace reasoning — confirm the precondition
first, then use the tool to do the mechanical part faster.

- **Heap state is hard to track by hand** (which chunk is where, is this tcache or
  fastbin, did safe-linking mangle my fd, where is `main_arena`) → **pwndbg** under
  gdb: `heap`, `bins`, `tcachebins`, `fastbins`, `vis` on the LIVE process. Break
  after the alloc/free you care about, then read the real chunk layout instead of
  guessing. Load: `gdb -q -nx -ex 'source /opt/pwndbg/gdbinit.py' ./target`.
  (This is the tool for the heap-menu / UAF / double-free signals in the router above.)
- **Gadget search** (need `pop rdi; ret`, a syscall gadget, a stack pivot, a
  one-shot `execve("/bin/sh")`) → **ropper** / **ROPgadget** on the binary for
  gadgets; **one_gadget** on the exact `libc.so.6` for magic gadgets. Always verify
  the gadget's constraints (one_gadget prints required register/stack state) against
  your actual state before committing budget to a chain.
- **Input → state mapping is complex / a VM or logic check decides success**
  (a bytecode interpreter, a multi-stage input validator, "what input reaches this
  branch / avoids this abort") → **angr** symbolic execution. API in this image is
  `import angr; claripy = angr.claripy` (angr 10 bundles claripy; there is no
  top-level `claripy` module). Pattern: `Project(path, auto_load_libs=False)` →
  symbolic `stdin`/argv BVS → `simulation_manager().explore(find=…, avoid=…)` →
  `found[0].posix.dumps(0)`.
  **Guard first — angr can state-explode:** only reach for it when the search space
  is bounded (short input, a check function, no giant loops / no crypto). Constrain
  input bytes (printable, fixed length), set `find`/`avoid` on concrete markers, and
  cap it (step/time budget). If it has not converged well inside your experiment
  budget, abandon it — do not let one angr run burn the whole run. angr is capability
  insurance for VM/logic-check targets; it is the WRONG tool for a heap or pure-ROP
  challenge (use pwndbg / ropper there).
- **glibc-version-specific heap behaviour** → still `heap.md` / `glibc_versions.md`
  first; pwndbg then confirms the real layout for THAT libc on the live process.

Precedence: identify the technique from the signal router, pick the matching tool
here, confirm the precondition, use the tool for the mechanical step, verify every
address/offset in-container. A tool that does not fit the signal is budget you will
not get back.
