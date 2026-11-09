# Leak strategies (the usual real first subproblem)

Under ASLR you need a leak before any libc/heap technique. Missing a leak is the most
common reason a "known" heap exploit stalls — treat it as its own subproblem.

## What you need to leak, and why
- **libc base** — for one_gadget, `system`, `_IO_*`, hook offsets. Source: an unsorted-
  bin chunk's `fd`/`bk` (points into `main_arena`), a GOT entry via a read primitive,
  or a format-string `%s` on a GOT pointer.
- **heap base** — required for safe-linking (≥2.32) to forge `fd`, and for overlapping
  chunk math. Source: a tcache `fd` of a freed chunk (mangled on ≥2.32 — demangle with
  the known heap position), or any pointer field `show()` reveals.
- **PIE/program base** — for ret2csu gadgets in the binary, GOT/function addresses.
  Source: a stack/return-address leak, or a partial overwrite that keeps the high bits.
- **stack/canary** — a byte-wise overflow + echo, or format-string `%p` scan; the canary
  is the low byte 0x00 + 7 random bytes, leak it before overflowing past it.

## Techniques
- **unsorted-bin → main_arena**: free a chunk too big for tcache (or after filling
  tcache); its `fd` now points near `main_arena`. `show()` it → libc base after
  subtracting this libc's `main_arena` offset.
- **format string**: `%p`/`%N$p` to walk the stack; `%s` on a planted GOT/libc pointer
  to dereference. Also the primary arbitrary-write primitive (`%n`).
- **partial overwrite (no leak needed)**: overwrite only the low 1–2 bytes of a return
  address/pointer. The low 12 bits are page-aligned-invariant under ASLR, so a 1-byte
  (or 1.5-byte with a brute of 1 nibble) overwrite can retarget within the same page —
  useful to call a nearby `win`/gadget when you have no leak at all.
- **GOT read**: if the menu has a "show/print" that indexes an array, read a GOT slot
  to get a libc function address directly.

## Order of operations
1. Can I get libc base cheaply? (unsorted-bin leak is usually easiest on a heap menu.)
2. Do I also need a heap leak? (Yes if libc ≥ 2.32 and I will forge tcache/fastbin fd.)
3. Only then build the write→RCE chain (hook pre-2.34, else FSOP). Confirm every offset
   against the EXACT shipped libc.
