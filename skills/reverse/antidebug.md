# Anti-debug / anti-analysis

## When this fits
The program behaves differently under a debugger, or actively checks for one: a
`ptrace(PTRACE_TRACEME)` early in `main`, reads of `/proc/self/status` (TracerPid) or
`/proc/self/stat`, timing checks (`rdtsc`, `clock`, two time reads bracketing a region),
`int3`/`SIGTRAP` handlers, `getenv("LD_PRELOAD")`/`LINES`/`COLUMNS` checks, `ptrace`-based
self-tracing, or it simply exits/garbles the check when run under gdb. Symptom: static
reading looks solvable but gdb runs diverge or exit early.

## Procedure (our words)
1. **Locate the check.** Find the anti-debug call (ptrace/open of /proc/.../status/
   rdtsc pair) and *what it gates* — usually a branch to an early `exit` or a path that
   corrupts the real computation.
2. **Choose a bypass:**
   - **Patch it out (static).** NOP the call or flip the branch so the "not traced" path
     always runs. Patch a *writable copy* of the binary in `/work` (root FS and `/input`
     are read-only): `cp /input/target /work/t; <patch>; chmod +x /work/t`. Patch with a
     Python byte edit at the file offset (`objdump`/`readelf` gives vaddr→offset).
   - **Avoid the debugger entirely.** Prefer **static** reconstruction or **angr**
     (symbolic execution doesn't call real `ptrace`; it models the syscall, so most
     anti-debug simply doesn't fire). This is usually the least-effort route.
   - **Defeat the check at runtime.** Under gdb, set a breakpoint and force the ptrace
     return / TracerPid to 0, or `set` the branch flag. Works but is fiddly; patch or
     angr first.
3. **Then solve the real logic** (`constraints.md` / `vm.md`) on the now-clean binary.

## angr note
angr models syscalls instead of executing them, so `ptrace`, `/proc` reads and timing
usually return benign values and the anti-debug branch is never taken — you often get the
bypass for free. If a check reads something angr models wrong, `hook` that call to return
the "clean" value. This is why, for an anti-debug binary, trying angr early is cheap.

## Failure signals → what to do
- Patched binary still diverges → there is a second check (anti-debug often comes in
  pairs: ptrace + timing); find and neutralize all of them.
- Patch offset wrong (binary crashes) → recompute vaddr→file-offset from the section
  headers; PIE shifts base, so patch by file offset, not runtime address.
- angr returns quickly with no `found` → the check gated the whole computation; make sure
  WIN/FAIL addresses are past the anti-debug branch.

## Not this
A program that just needs the right input and runs fine under gdb has no anti-debug —
don't invent one. This frame is only for active debugger/analysis detection.
