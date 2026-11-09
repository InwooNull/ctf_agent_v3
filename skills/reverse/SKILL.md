# Reverse cheat-sheet (C1 knowledge pack) — router

Knowledge only, in our own words: *which* reverse technique fits *which* observation,
and *which* tool does the mechanical part. It names no challenge and contains no answer
— you still recover the logic and the flag in-container, with the same tools and budget
as C0. Load a detail file only when the signal below matches.

## How to use
1. `info` first, then triage the binary inside an experiment: `file`, `checksec`-style
   header read (`readelf -hSd`), `strings`, entry point, and a quick `objdump -d`
   skim. Decide the *shape* before disassembling everything.
2. Match the dominant signal to a technique, open the detail file for the procedure and
   the failure signals, then decide: **manual** (read/emulate by hand) or **angr**
   (let the symbolic engine search for the input). Confirm every address/offset
   in-container before trusting it.
3. The flag is almost always *computed from an input the program checks*. The job is to
   recover the check, then invert it (solve for the input) — not to find a stored
   string. If `strings` shows the flag, suspect a decoy.

## Signal → technique → tool
- **a fetch/decode/execute loop over a byte array, an opcode `switch`, a
  "program"/"bytecode"/"rom" buffer** → it is a **VM / bytecode interpreter**;
  reconstruct the ISA, then recover the check. Tool: **angr** to search for accepted
  input, or a hand-written emulator → `vm.md`
- **one giant function, a `while(state){ switch(state){...} }`, dispatcher variable
  reassigned each block, no normal if/else nesting** → **control-flow flattening**;
  rebuild the real block order. Tool: **angr** (treat the check as a path constraint and
  let it find the input) or manual de-flattening → `cfg_flatten.md`
- **a per-byte / per-char check against constants, a comparison loop, `input[i] ^ k
  == c`, a product of small checks** → **constraint / crackme**; collect the
  constraints and solve. Tool: **angr** `find`/`avoid` on the success/failure address,
  or z3 by hand → `constraints.md`
- **`ptrace`, `/proc/self/status` TracerPid, timing (`rdtsc`), `int3`, `getenv`
  checks, or gdb visibly misbehaving** → **anti-debug / anti-analysis**; patch it out
  or run static/symbolic instead of under the debugger → `antidebug.md`
- **stripped, no symbols, static, packed, or `main` not obvious** → recover the entry
  point and the real logic before anything else → `stripped.md`

## angr: guard it FIRST, before you run it
angr is powerful but can **state-explode** (hang / OOM) on exactly the big VM and
flattened binaries you most want it for. Never launch a bare `explore()`. The guards
are not optional — set them before the first run:
- **Bound the input.** Make the input a fixed-length symbolic `BVS`, constrain each
  byte to a plausible range (printable, or the flag charset), and feed it on stdin or
  into the buffer the program reads — not an unconstrained file/world.
- **Give `find` AND `avoid`.** `find` = the address that prints success / the
  `puts("correct")`; `avoid` = the failure/`exit` address(es). Without `avoid`, angr
  wanders every wrong path. Read these addresses off `objdump`/gdb first.
- **Cap the search.** Use `LAZY_SOLVES`, a step/`n` bound, and veritesting
  (`angr.exploration_techniques` or `veritesting=True`) for flattening; set a wall-clock
  timeout and kill the run if state count explodes. A capped run that fails fast tells
  you more than one that hangs to the budget wall.
- **Hook the expensive stuff.** If the binary does heavy I/O, hashing, or a syscall
  angr models poorly, `hook` it or `symbion`-skip it rather than letting angr execute it
  symbolically.
- **angr is the WRONG tool** when the logic is tiny (just read it), when it is one clean
  per-byte xor (invert it directly — faster than loading angr), or when the "check"
  needs real crypto/network/filesystem state angr can't model. Reach for it for VM /
  flattening / many-constraint crackmes, not for everything.

## Runtime notes (this image: ctfagent-rev:0.2)
- angr: `import angr; claripy = angr.claripy` (10.x bundles claripy; there is no
  top-level `claripy` module). Set `HOME=/work` (or `/opt/ctfagent/angr_home`) so it can
  write its cache; the root FS is read-only. If angr trips `getpwuid`/passwd lookups,
  shim `pwd.getpwuid` to return a synthetic entry (uid 65534 has no `/etc/passwd` row).
  Load with `proj = angr.Project(path, auto_load_libs=False)` to stay fast.
- Everything runs `--network none`, non-root, read-only root FS, scratch at `/work`.
  This is *analysis*: nothing here weaponizes a target, so it does not trip the
  orchestrator's exploit safeguards.
