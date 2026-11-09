# Stripped / no symbols / packed

## When this fits
`file` says "stripped"; `nm` shows nothing; there is no obvious `main`; the binary is
static (libc folded in) or packed (high-entropy section, a tiny loader that unpacks into
memory, a UPX-like stub). The logic is all there but you can't find your way in.

## Procedure (our words)
1. **Recover the entry and `main`.** The ELF entry (`readelf -h` → Entry point) is
   `_start`; for a glibc program `_start` passes `main` to `__libc_start_main` as the
   first argument — read that argument (loaded into `rdi` just before the call) to get
   `main`'s address. For a static binary, identify libc functions by their shape/strings
   to cut through the noise.
2. **Anchor on observables.** `strings` for prompts/format strings, then find the code
   that references those addresses (`objdump -d | grep` the address) — that lands you in
   the interesting function even without symbols. Syscalls and libc calls (`read`,
   `write`, `strcmp`, `memcmp`, `printf`) are strong anchors for where input is handled.
3. **If packed, unpack first.** A packer = small loader + high-entropy blob. Either run it
   under gdb and dump memory after the unpack stub jumps to the real entry (break at the
   tail jump, dump the now-decoded region), or recognize a known packer and reverse its
   stub. You cannot usefully disassemble packed bytes — unpack, then restart triage.
4. **Then classify** the real logic (VM / flattening / constraints) and solve it.

## angr note
angr loads a stripped binary fine (it works on addresses, not symbols) — give it the
entry state and the WIN/FAIL *addresses* you found in step 2. For a static binary use
`auto_load_libs=False` and consider `angr.Project(..., main_opts={'base_addr':0})` only if
you need a fixed base. Packed binaries must be unpacked before angr sees real code.

## Failure signals → what to do
- Can't find `main` → you may be looking at a static/PIE binary; use the
  `__libc_start_main` argument (step 1) or anchor via `strings`→xref (step 2).
- Disassembly is nonsense / invalid opcodes → the region is packed or encoded; unpack or
  decode before trusting any instruction.
- `nm`/symbols empty but `file` not "stripped" → it may be a Go/Rust/static binary with
  its own symbol scheme; look for the language's runtime strings to orient.

## Not this
If symbols are present and `main` is obvious, skip this file — go straight to classifying
the logic.
