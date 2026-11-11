# Shellcode & seccomp (ORW when execve is blocked)

## When this fits
The program copies your bytes into an **executable** region (RWX buffer, `mmap`/`mprotect`
with PROT_EXEC, a JIT page) and jumps to them, OR you reached RIP control and the stack is
executable. You supply machine code, not a ROP chain. If a **seccomp** filter is present,
a plain `execve("/bin/sh")` shellcode will be killed — read the filter first.

## Writing the shellcode
- `pwntools`: `context.arch='amd64'` (or `'i386'`); `asm(shellcraft.sh())` for
  `execve("/bin/sh",0,0)`. Mind the architecture — **i386 vs amd64 syscall numbers and
  calling convention differ** (int 0x80 / eax vs syscall / rax); a 64-bit number in a
  32-bit stub silently calls the wrong syscall.
- Keep it position-independent and NUL-aware: a stub copied via `strcpy`/`read` into a
  fixed buffer must avoid forbidden bytes (see constraints below).

## Byte/length constraints (match the input path)
- **No-NUL** (copied by `strcpy`) → avoid `\x00` (xor-zero instead of `mov 0`, use
  `push`/`pop`), or use an encoder/`xor` decoder stub.
- **Alphanumeric / printable only** → use an alphanumeric encoder (pwntools
  `encoders.encode`, or the classic `ascii` shellcode builders) — a short decoder in the
  allowed charset unpacks the real payload.
- **Too short a buffer** → write a tiny **stager**: a `read(0, buf, N)` stub that pulls the
  full shellcode into a known RWX page and jumps to it; or an **egghunter** that scans
  memory for a tagged second payload you planted elsewhere.

## seccomp: detect, then switch to ORW
`seccomp-tools` is **not in this image**. Detect and read the filter by hand:
- Tells: the binary calls `prctl(PR_SET_SECCOMP, ...)` / `seccomp()` / loads a BPF program;
  `strings`/`objdump` show `prctl`, `seccomp`, or a `sock_filter` array; an `execve`
  attempt dies with `SIGSYS` (signal 31) instead of running.
- Recover the policy: read the BPF array out of the binary (it's a table of `sock_filter`
  structs — decode the opcodes), or single-step the `prctl` call in **gdb/pwndbg** and
  inspect the installed program. Decide which syscalls are **allowed** vs **killed**.
- Classic policy: `execve`/`execveat` blocked, but `open`/`openat`, `read`, `write`
  (and often `mmap`, `exit`) allowed.

**ORW shellcode** (when exec is dead): `open("flag",0)` → `read(fd, buf, n)` →
`write(1, buf, n)`. `shellcraft.cat('/flag')` or `shellcraft.open/read/write` build it.
Variations when a primitive is filtered:
- `open` blocked but `openat` allowed → use `openat(AT_FDCWD, ...)`.
- `read`/`write` blocked → `sendfile(1, fd, 0, n)`, or `mmap` the file and `write` the
  mapping, or `preadv`/`pwritev`.
- only `exit`-family left → a **side channel**: leak the flag bit-by-bit through exit code
  or timing (an oracle loop), slow but works when I/O is fully banned.

## Related
Big stack overflow + a `syscall` gadget but NX on (can't run bytes) → set up the syscall
via **SROP**, see `rop.md`. Need a leak before any of this → `leaks.md`.

## Failure signals → pivot
- Jump to your bytes → `SIGSEGV` → the region isn't executable (NX); you need ROP
  (`rop.md`) or an `mprotect` chain, not raw shellcode.
- `execve` dies with `SIGSYS` → seccomp; stop retrying exec, switch to ORW.
- ORW reads nothing → wrong filename/path or fd handling; confirm the flag's path and that
  `open` actually returned a valid fd in-container.

## Verify
The flag is confirmed only when the running process prints it (ORW `write`, or the shell
reads it) in-container. Never report a flag the shellcode merely *should* have produced.
