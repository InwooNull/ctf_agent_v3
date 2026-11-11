# Non-C runtimes (Go / Rust / .NET / Java / WASM / PyInstaller)

## When this fits
`file`/`strings` show a managed or non-C runtime, and treating the binary as a plain
stripped C program (`stripped.md`) wastes budget. **Recognize the runtime first** — the
recovery route is completely different per language. This image is lean (binutils, `file`,
`gdb`, `xxd`, angr); the language's dedicated decompiler is usually **absent**, so each
section gives the stdlib/manual fallback.

## Fingerprint (how to tell which runtime)
- **Go** → strings like `go:buildid`, `runtime.`, `GOROOT`, a `.gopclntab` section; looks
  "stripped" but is not — the pclntab holds function names.
- **Rust** → mangled `_ZN...` symbols, panic strings with source paths
  (`src/main.rs:line`), `rustc`/`cargo` in strings; large static binary.
- **.NET** → a PE whose CLR header / `mscoree.dll` import is present; strings show
  `#Blob`, `#Strings`, `<Module>`, method names in clear.
- **Java/Kotlin** → a `.jar`/`.class`; class files start with magic `CA FE BA BE`; or an
  APK (a zip with `classes.dex`, magic `dex\n035`).
- **WASM** → magic `\0asm` (`00 61 73 6d`), a `.wasm` file or embedded in a web bundle.
- **PyInstaller/py2exe** → strings `pyi`, `_MEI`, `PyInstaller`, a packed archive appended
  to a bootloader.

## Per-runtime approach
- **Go.** The `.gopclntab` recovers function names even when "stripped" — parse it (angr's
  loader, or a pclntab parser) to name functions, then read the check as usual. Go
  **strings are length-prefixed, not NUL-terminated**, so `strings` shows them concatenated
  into one blob — slice by the length field, don't trust NUL boundaries. Args/structs use
  Go's own ABI; focus on the function that consumes the input.
- **Rust.** Symbols are usually present (demangle `_ZN`); panic messages pinpoint the
  logic and often the exact check. Skip the huge `std`/`core` prologue — start from the
  caller of `std::rt::lang_start` (the real `main`). The check is ordinary machine code;
  angr works if you target just the check function.
- **.NET.** It is CIL, not native — a native disassembler shows only the JIT stub.
  Decompilers (ILSpy/dnSpy/`monodis`) are absent here; fallback: the **metadata tables are
  readable** — `strings` recovers method and string names, and the `#US` (user string) heap
  often contains the flag-check constants directly. If a python `dnfile`/`pythonnet` is
  available, dump methods; otherwise bundle for a decompiler handoff.
- **Java / APK.** A jar/class is a zip of bytecode — `unzip` it. `javap -c` (if a JDK is
  present) disassembles a `.class`; a decompiler (jadx/cfr/procyon) is cleaner but absent
  here. For an **APK**, `classes.dex` is the target (dex→jar→read); native logic may hide
  in `lib/*/*.so` (then it's a normal ELF → other reverse files). Constant-pool strings
  often leak the check.
- **WASM.** `wasm2wat` (wabt) is absent; if the challenge ships the `.wat` text read it
  directly, else parse the binary sections by hand or run it under a python `wasmtime`/
  `wasmer` if present. WASM crackmes are usually a simple per-byte check in one exported
  function — find the export, read the loop, invert it.
- **PyInstaller/py2exe.** Extract the embedded archive (`pyinstxtractor`-style: the archive
  is appended to the loader) to get `.pyc`, then decompile (`pycdc`/`decompyle3`) or, if
  those are absent, `dis` the bytecode with stdlib `dis` after fixing the pyc header — it's
  Python, so recovering the source-level check is usually quick.

## angr note
angr runs on the **native** ones (Go, Rust, static) because they are machine code, but the
fat runtime causes state explosion — hook/`avoid` the runtime and point it only at the
check function (see `vm.md` for the guarded setup). It does **not** help on CIL/JVM/WASM
bytecode (not native).

## Failure signals → pivot
- You disassemble and it's a thin stub that calls a VM/JIT → it's managed bytecode (.NET/
  JVM/WASM), not native; switch to the metadata/bytecode route above.
- Go binary looks hopeless as "stripped C" → you missed the pclntab; parse it for names.
- The real logic is in a bundled `.so` → treat that ELF with the normal reverse flow.

## Not this
A native C/C++ binary with a VM-style dispatch loop → `vm.md`; flattened control flow →
`cfg_flatten.md`; per-byte constraint check → `constraints.md`.

## Verify
Recover the **check**, invert it for the input, and confirm in-container that the input is
accepted before reporting. A string that merely *looks* like the flag in a dump is a
decoy until the program validates it.
