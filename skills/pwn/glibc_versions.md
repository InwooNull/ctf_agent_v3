# glibc version differences that break heap recipes

Read the version first: `strings libc.so.6 | grep "GNU C Library"`, or from the
challenge's shipped loader/libc. Branch your plan on it — most "my exploit should work
but doesn't" is a version mismatch.

## Timeline of the traps
- **2.23** — pre-tcache. fastbin/smallbin attacks, `__malloc_hook` via House of
  Spirit / fastbin dup are classic. No tcache key, no safe-linking.
- **2.26** — tcache introduced. Freed small chunks go to a per-thread cache first;
  many classic bin attacks now need the tcache filled (7 frees) before chunks reach
  fastbin/unsorted. tcache poisoning becomes the easiest write primitive.
- **2.27** — common on Ubuntu 18.04. tcache present, NO key yet → tcache double-free is
  trivial here. Good target for the simplest poisoning.
- **2.29** — tcache gains the double-free `key`; top-chunk size sanity kills House of
  Force. `unsorted_bin` integrity check added.
- **2.31** — common on Ubuntu 20.04. Hooks still present. Tightened checks but tcache
  poisoning + hook overwrite still works given a leak. (This is the version behind the
  CryptoPwn-style "glibc-2.31 heap, no leak" wall — the subproblem is the LEAK, not a
  missing hook.)
- **2.32** — **safe-linking**: tcache/fastbin `fd` stored as `(pos >> 12) ^ ptr`. You
  now need a heap address leak to forge any pointer; also an alignment check on the
  demangled pointer.
- **2.34** — `__malloc_hook`/`__free_hook`/`__realloc_hook` REMOVED. Hook overwrite is
  dead; pivot to FSOP (`_IO_FILE`) or GOT/return-address overwrite.
- **2.35** — common on Ubuntu 22.04. FSOP via House of Apple 2 is the standard RCE from
  a write primitive; `_IO_FILE` vtable check means you target `_IO_wfile_jumps`.

## Practical rules
- Missing hooks? libc ≥ 2.34 → don't look for `__free_hook`; go FSOP.
- Pointer write "works" in a debugger but the chunk address looks scrambled? safe-linking
  (≥2.32) → leak a heap address and mangle your `fd`.
- "double free detected" on a clean double-free? ≥2.29 tcache key → change the key or
  use fastbin.
- Always match the EXACT shipped libc for offsets (`main_arena`, one_gadget, `_IO_*`).
  If the materials ship a libc but no matching loader, that is a deploy fault, not a
  technique — record it and move on (don't spend budget fighting a broken loader).
