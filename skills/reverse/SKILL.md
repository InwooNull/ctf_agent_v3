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
- **a non-C runtime** (Go `.gopclntab`/`go:buildid`, Rust panic paths, .NET/CLR, a
  `.jar`/`.class`/APK, WASM `\0asm`, PyInstaller `_MEI`) → recognize the runtime first;
  the recovery route differs per language → `lang_runtime.md`

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

## Runtime notes (this image: ctfagent-rev:0.3)
- angr: `import angr; claripy = angr.claripy` (10.x bundles claripy; there is no
  top-level `claripy` module). Set `HOME=/work` (or `/opt/ctfagent/angr_home`) so it can
  write its cache; the root FS is read-only. If angr trips `getpwuid`/passwd lookups,
  shim `pwd.getpwuid` to return a synthetic entry (uid 65534 has no `/etc/passwd` row).
  Load with `proj = angr.Project(path, auto_load_libs=False)` to stay fast.
- Everything runs `--network none`, non-root, read-only root FS, scratch at `/work`.
  This is *analysis*: nothing here weaponizes a target, so it does not trip the
  orchestrator's exploit safeguards.

## In-sandbox decompiler lane (Ghidra + REA)  [all in-container, --network none]
Everything above is the `objdump`/angr lane. This lane adds a real **decompiler**
(Ghidra 12.2 headless) and a **multi-format RE orchestrator** (REA / `rea` CLI) for
when reading disassembly by hand or pointing angr at it isn't enough. It all runs
INSIDE `ctfagent-rev:0.3` — `--network none`, read-only root, non-root, cap-drop ALL —
so even REA's dynamic features execute only in the container. REA treats Ghidra as a
native *provider*, not an LLM backend: `--provider ghidra` is pure static decompilation
with **no model and no network**. **Never run `rea` on the host.**

Reach for it when:
- **You need C-like decompiled pseudocode** of a dense function, faster than reading
  `objdump -d` → `rea decompile <bin> 0xADDR --provider ghidra --json` (pseudocode),
  `rea function <bin> main --provider ghidra --json` (function dossier), or Ghidra
  directly: `analyzeHeadless /work proj -import <bin> -postScript <GhidraScript>`. The
  signal→technique router above still picks the *technique*; this is the mechanical
  decompile step. Confirm every address/offset in-container before trusting it.
- **The target isn't a plain C ELF** — an APK/.NET/WASM/JS-Electron or a runtime
  `lang_runtime.md` names, where `objdump`+angr don't apply → `rea analyze <target>
  --provider ghidra --json` for the overview, or the JS path
  `npx -y rea-agents@latest analyze-javascript-application /work/app --json`.
- **Quick triage / ELF hardening** (PIE/NX/RELRO/canary, strings, imports in one shot)
  → `rea analyze <bin> --provider ghidra --json`. `rea providers --json` lists engines.
- `REA_ANALYSIS_PROVIDER=ghidra` is already the image default, so `--provider ghidra`
  is optional but kept explicit above. Set `HOME=/work` (writable) as for angr.

Boundaries that still hold: **analysis only** — this recovers logic, it does not
weaponize a target (same bar as the angr note). The flag is still **recovered and
verified in-container**: a string Ghidra/REA prints is a *candidate*, NOT a flag, until
the program's own check accepts the recovered input. **Never auto-submit**; surface the
candidate + evidence to the user. The 7 governance files and `config/sandbox.json` stay
byte-identical; the only code change for this lane is the rev harness raising the rev
container's memory ceiling to 2g (see below).

**Cost & runtime — this lane is slow and heavy; reach for it only when objdump/angr
can't do the job.** The container is ephemeral (`--rm`), so every `rea`/Ghidra call
re-imports and re-analyzes the target from scratch — ~85s for a tiny ELF on 1 CPU,
minutes for a real binary.
- **Memory:** the Ghidra JVM OOMs at the pinned 256m default; the rev harness gives
  this image 2g (measured minimum for a clean run). You don't set this — it's automatic.
- **Timeout:** pass a long experiment timeout — `run_experiment({... "timeout": 300})`
  — or the 30s default kills Ghidra mid-analysis. The image sets
  `REA_GHIDRA_STARTUP_TIMEOUT_MS=600000`; lower it via env for a quick target.
- **Scratch:** Ghidra/REA need a writable temp dir; the root FS is read-only, so
  `HOME=/work` and `TMPDIR=/work` (the image's sitecustomize sets both — keep them).
- **Many-function dumps — use `ghidra-decompile`, not repeated `rea`:** `rea`
  re-imports and re-analyzes on *every* call (~60s each, no cache — the harness's
  shared-`/work` `persist_work` does NOT speed it up). To dump several functions of one
  binary, call the baked **`ghidra-decompile <bin> [func]`** wrapper from your
  experiment code instead: it imports+analyzes once (~38s), then reuses the saved
  project per call (~33s each — a JVM+script-compile floor, not re-analysis), and prints
  pseudocode as JSON `[{name,entry,c}]`. Measured break-even is ~3 queries; for 1–2
  lookups `rea decompile <bin> <addr> --provider ghidra --json` is simpler. The wrapper
  handles the read-only-`/tmp` (`java.io.tmpdir`) and passwdless-uid plumbing for you.
