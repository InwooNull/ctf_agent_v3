# Heap techniques (glibc malloc)

All recipes assume you confirmed the libc version first (`glibc_versions.md`). Addresses
and offsets are never reused from memory — derive them in-container each run.

## Picking the technique from the primitive you have
| you have | aim for |
|---|---|
| UAF / double-free on a small chunk | tcache poisoning (2.26+) or fastbin dup (older) |
| overflow of a chunk header | corrupt size → overlap, or unsorted-bin attack |
| one freed chunk + a show() | unsorted-bin leak of `main_arena` (→ libc base) |
| arbitrary write, libc ≥ 2.35 | FSOP via `_IO_FILE` (House of Apple 2) |

## tcache poisoning (2.26+)
Free a chunk into tcache, use a UAF/overflow to overwrite its `fd` (the forward
pointer) with a target address, then two mallocs of that size hand you a chunk *at*
the target. Classic targets: `__free_hook`/`__malloc_hook` (removed in 2.34 — see
below), a GOT entry, or a stack return address.
- **2.29+ tcache key**: each tcache chunk stores a `key`; a naive double-free trips
  "double free detected". Bypass by changing the key (one byte) between the two frees,
  or route through fastbin instead.
- **2.32+ safe-linking**: the `fd` is stored mangled as `(addr >> 12) ^ fd`. You must
  know the chunk's own address (the heap leak) to forge a valid pointer; a raw target
  address written directly will fail the alignment check. Leak a heap address first.
- **2.34**: `__malloc_hook`/`__free_hook`/`__realloc_hook` are gone. Pivot to FSOP or
  overwriting a GOT/return address instead of a hook.

## fastbin dup (pre-tcache, or when tcache is full/bypassed)
Double-free a fastbin chunk so the fastbin links to itself; allocate, overwrite `fd`
to a fake chunk near the target (the `size` field must pass the fastbin size check —
often needs a "fake size" nearby, e.g. `__malloc_hook - 0x23` alignment trick).

## unsorted-bin leak (the usual libc leak)
Free a chunk larger than tcache max (or when tcache is full) so it lands in the
unsorted bin; its `fd`/`bk` now point into `main_arena` inside libc. A `show()` on it
leaks a libc address → subtract the known `main_arena` offset for this libc → libc base.

## House of Force (pre-2.29) / House of Apple (2.35+)
- **House of Force** (removed when the top-chunk size check was added, ~2.29): overwrite
  the top chunk size with a huge value, then a crafted large malloc moves the top chunk
  to an arbitrary address. Dead on modern libc.
- **House of Apple 2** (2.35+ FSOP): craft a fake `_IO_FILE` whose `vtable` points into
  `_IO_wfile_jumps` and drive `_IO_wfile_overflow`/`_wdoallocbuf` to call a controlled
  pointer; reach it via `_IO_list_all` or by overwriting `stdout`/`stderr`. This is the
  modern replacement for hook overwrites once a libc leak + one write are in hand.

## Checklist before spending budget
- Leak obtained? (libc base AND, for safe-linking, a heap address.) If not → `leaks.md`.
- Technique matches the libc version? → `glibc_versions.md`.
- Target still exists in this libc (hooks removed in 2.34)?
