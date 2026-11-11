# Format string (uncontrolled `printf`)

## When this fits
Your input reaches a `printf`-family function as the **format argument itself** —
`printf(buf)`, `fprintf(f, buf)`, `snprintf(..., buf)`, `syslog(pri, buf)` — not
`printf("%s", buf)`. Tell from the behaviour: type `%p %p %p` (or `AAAA.%p.%p.%p`) and
you get stack words / hex back, or a bare `%s` crashes. This one bug gives both a **read**
(leak) and a **write** (`%n`) primitive — usually you leak first, then write.

## Find your offset first (where your buffer lands in the va_list)
Send `AAAAAAAA` + `%p ` repeated, or pwntools' autodetect. Find which positional argument
prints `0x4141414141414141` — that index `k` is where your controlled bytes sit, so a
later `%k$...` reads/writes through a value you placed on the stack. Everything below
uses **positional** `%k$` specifiers; a non-positional spray wastes the fixed arguments
first and is hard to aim.

## Read primitive (leaks)
- `%k$p` / `%k$lx` — dump the k-th stack slot. Walk k to find saved pointers: a **libc**
  address (return into `__libc_start_main`), a **PIE** base (a return into the binary), a
  **stack** address, and the **canary** (a qword ending in `00`, not a valid pointer).
- `%k$s` — dereference the k-th slot as a pointer and print the C string there. Put a GOT
  address in your buffer and `%s` it to leak a libc function's runtime address → libc base.

## Write primitive (`%n` family)
`%n` writes the **number of bytes printed so far** to the address in that argument slot.
Print N chars with a width field (`%Nc`), then `%k$n` writes N to `*arg_k`.
- `%hn` writes 2 bytes, `%hhn` writes 1 byte — split a 4/8-byte target into short/byte
  writes so you don't have to print billions of characters. Order the chunks by ascending
  value and account for bytes already printed.
- Place the **target addresses** in your buffer (64-bit: put them at the end, after the
  format directives, so they are at predictable slots and contain no premature NUL that
  truncates the string).
- Let `pwntools` do the arithmetic: `fmtstr_payload(offset, {addr: value}, write_size='short')`.
  Hand-roll only when a filter forbids what it emits.

## What to overwrite
- **GOT entry** of a function called after your write (`printf`→`system`, or →a
  `one_gadget`). Simplest when Partial RELRO (GOT writable).
- **return address** on the stack (you leaked a stack addr; one-shot).
- **`__malloc_hook`/`__free_hook`** — only **pre-2.34** (removed after). On ≥2.34 target
  the GOT, a saved return, or an exit-handler / `__exit_funcs` pointer instead.
- Full RELRO → GOT is read-only; pivot to a return address or a function pointer in
  writable memory.

## Failure signals → pivot
- `*** %n in writable segment detected ***` or `%n` silently ignored → **FORTIFY**
  (`_FORTIFY_SOURCE`) rejects `%n` to a writable format; you keep the **read** primitive
  but must get control another way (overwrite a non-`%n` target you can still reach, or
  find a second bug).
- Only one shot at the format string → leak and write in the *same* payload, or overwrite
  a loop/`main`-return so you get fed again.
- Offset `k` prints the wrong thing after you lengthen the payload → your buffer moved
  (alignment/length changed which slot holds it); re-find k with the final-length payload.

## Verify
Confirm the leak is a plausible address (correct high bytes / page alignment) and the
write landed by observing the hijacked call take effect in-container — never report a flag
until the target itself yields it. Derive every address in-container each run.
