# ROP / stack techniques (NX on, no win())

When the bug is a stack overflow and NX is set, chain existing code. Gadgets from the
binary (ROPgadget/ropper) and, after a libc leak, from libc.

## ret2libc
After a libc leak: `pop rdi; ret` → `&"/bin/sh"` (in libc), then `ret` (stack align,
movaps!) then `system`. On modern libc a misaligned stack segfaults inside `system` —
add an extra `ret` to 16-byte-align before the call. `one_gadget` on the exact libc is
often shorter (watch its constraints: certain registers/`[rsp+x]==NULL`).

## ret2csu (no `pop rdi` gadget in a static/PIE binary)
`__libc_csu_init` has two gadget clusters: one pops `rbx rbp r12 r13 r14 r15 ret`, the
other does `mov rdi,r13d? ... call [r12+rbx*8]` style setup then `rdi/rsi/rdx` from
`r13/r14/r15`. Use them to control the first three args and call a GOT/pointer target
when the binary lacks direct arg gadgets. (Absent in some 2.34+ builds that dropped
`__libc_csu_init` — then look for `__libc_start_main` cold gadgets or a libc leak.)

## SROP (sigreturn)
If you can call `sigreturn` (syscall 15; often via a `syscall; ret` gadget and
`rax=15`), push a fake `sigcontext` on the stack to set ALL registers at once, including
`rip`, `rsp`, and syscall args. Great when gadgets are scarce but you have a big stack
overflow and a `syscall` gadget — e.g. set up `execve("/bin/sh",0,0)` directly.

## stack pivot
Short overflow (only a few qwords past saved rip)? Pivot `rsp` to a buffer you fully
control: `leave; ret` (sets rsp=rbp then pops) or `pop rsp; ret` / `xchg rax,rsp`. Put
the real chain where the controlled buffer lives (often a known .bss or a heap/leaked
address) and jump there.

## Order
1. Enough overflow for a full chain? If not → stack pivot to a bigger controlled buffer.
2. Have a libc leak? ret2libc / one_gadget. No leak but static? syscall ROP (execve) or
   ret2csu to a syscall. No leak, dynamic, tiny overflow? partial overwrite (`leaks.md`).
3. Mind stack alignment (extra `ret`) and one_gadget constraints; verify in-container.
