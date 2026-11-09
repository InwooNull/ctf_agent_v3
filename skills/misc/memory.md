# Memory forensics (volatility3)

**When:** a large "data" blob that is a RAM capture — process lists, registry hives,
network state live inside it. Confirm first: `strings dump | grep -iE 'windows|system32|
\\Device\\|linux version'` usually reveals the OS; the file size is often a round power
of two.

**Symbols & cache are baked (misc:0.7).** The image bundles vol3's Windows/Mac/Linux
symbol ISF packs AND a pre-built symbol-identifier index, so Windows/Mac dumps resolve
offline on a cache HIT — no network, and no multi-minute cold scan of the 801 MB Windows
pack. The analyzer seeds `/work` from the baked cache (`$VOL_BAKED_CACHE`, default
`/opt/ctfagent/volcache`) and sets `HOME=/work XDG_CACHE_HOME=/work` before running vol3.
If you drive `vol` yourself, do the same two things first, or the first lookup will stall:

```sh
export HOME=/work TMPDIR=/work XDG_CACHE_HOME=/work
cp -a /opt/ctfagent/volcache/. /work/        # seed the baked identifier cache
vol -q -f dump windows.info                   # now a cache hit (~seconds), not a scan
```

**Procedure (Windows):**
1. `vol -f dump windows.info` — confirms it is a Windows image and picks the profile
   (vol3 has no `imageinfo`; `windows.info` is the orientation step).
2. Pick the plugin from what you need:
   - processes / hidden → `windows.pslist`, `windows.psscan`, `windows.pstree`
   - command lines / what ran → `windows.cmdline`, `windows.consoles`
   - network → `windows.netscan`, `windows.netstat`
   - files in memory → `windows.filescan`, then `windows.dumpfiles --virtaddr <addr>`
   - registry → `windows.registry.hivelist`, `windows.registry.printkey --key '...'`
   - credentials → `windows.hashdump`, `windows.lsadump`, `windows.cachedump`
   - injected code → `windows.malfind`
3. Carve a found file/process to disk, then analyse it with the normal tools.

**Procedure (Linux) — symbols are NOT pre-bundled (kernel-build specific).** Generic Linux
symbols cannot be baked, so when the challenge ships its kernel symbol material build the
ISF on the fly, fully offline, with the bundled `dwarf2json` + the `vol-linux-isf` helper:

```sh
# auto-discovers vmlinux/DWARF / System.map in /input, builds an ISF, runs the plugin
vol-linux-isf /input/dump linux.pslist.PsList
# or point it explicitly:
VMLINUX=/input/vmlinux SYSTEMMAP=/input/System.map vol-linux-isf /input/dump linux.bash.Bash
```
Under the hood: `dwarf2json linux --elf <vmlinux+DWARF> [--system-map <map>] > isf.json`
then `vol -s <isf dir> -f dump linux.*`. `linux.bash` (shell history) is often where a
flag or password hides; also `linux.pslist`, `linux.pstree`, `linux.proc.Maps`, `linux.elfs`.

**Failure signal → pivot:**
- No kernel symbol material for a Linux dump → `vol-linux-isf` prints a `##NEED##`
  `{"type":"tool_gap","reason":"no_kernel_symbols"}` marker (the pipeline logs it to
  `needs.jsonl`) and falls back to `strings`. Pull the artifact you were after (bash
  history, a config, a key) from `strings`/`bulk` instead of a symbol-dependent plugin.
- Windows plugin returns nothing → wrong plugin family; re-orient with `windows.info` /
  `windows.pstree` and follow the actual artifact (a filename, a process) the task hints.

**Verify:** a flag pulled from memory (a file, a command line, bash history) is still just
a string — confirm it against the challenge's checker/format before reporting.
