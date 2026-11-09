#!/bin/sh
# vol-linux-isf — offline Linux memory forensics for vol3 via dwarf2json.
#
# Linux symbols CANNOT be universally pre-bundled (they are kernel-build specific),
# so when a challenge ships its kernel symbol material we build the ISF on the fly,
# fully offline, and point vol3 at it with -s. No network is ever used.
#
#   usage: vol-linux-isf <dump> <plugin> [extra vol args...]
#
# Kernel symbol material is taken from these env vars, else auto-discovered in /input:
#   VMLINUX    an ELF vmlinux (or module) WITH DWARF debug info      (best single source)
#   SYSTEMMAP  a System.map-<ver> file (symbol name -> address)
#   DBGKERNEL  a standalone DWARF debug file (vmlinux.debug / *.ko.debug / dbg kernel)
#
# dwarf2json needs DWARF for the type layout; System.map alone yields symbols-only ISF
# (enough for banner match + a few plugins). We pass whatever is available.
#
# On success: prints vol3 output; exits 0.
# On no usable symbols: prints a single machine-readable marker line
#     ##NEED## {"type":"tool_gap","reason":"no_kernel_symbols"}
# then a strings fallback, and exits 0 (the host harness turns the marker into a
# needs.jsonl entry; label is strings-fallback, never "real structure").
set -eu

DUMP="${1:?usage: vol-linux-isf <dump> <plugin> [vol args...]}"
PLUGIN="${2:?missing plugin, e.g. linux.pslist.PsList}"
shift 2

ISF_DIR="${ISF_DIR:-/work/isf}"
mkdir -p "$ISF_DIR/linux"
OUT="$ISF_DIR/linux/challenge.json"

# --- auto-discover symbol material in /input if not given explicitly -------------
discover() {
  # $1 = description, echoes first match or empty
  find /input -maxdepth 4 -type f \( "$@" \) 2>/dev/null | head -1
}
: "${VMLINUX:=$(discover -name 'vmlinux' -o -name 'vmlinux-*' -o -name '*.vmlinux')}"
: "${DBGKERNEL:=$(discover -name 'vmlinux.debug' -o -name '*.debug' -o -name 'vmlinux-*-dbg')}"
: "${SYSTEMMAP:=$(discover -name 'System.map' -o -name 'System.map-*')}"

ELF="${VMLINUX:-$DBGKERNEL}"

build_isf() {
  # Prefer ELF+DWARF (full types); add System.map if present. Fall back to map-only.
  if [ -n "${ELF:-}" ] && [ -f "$ELF" ]; then
    if [ -n "${SYSTEMMAP:-}" ] && [ -f "$SYSTEMMAP" ]; then
      dwarf2json linux --elf "$ELF" --system-map "$SYSTEMMAP" > "$OUT" 2>/work/d2j.err
    else
      dwarf2json linux --elf "$ELF" > "$OUT" 2>/work/d2j.err
    fi
  elif [ -n "${SYSTEMMAP:-}" ] && [ -f "$SYSTEMMAP" ]; then
    dwarf2json linux --system-map "$SYSTEMMAP" > "$OUT" 2>/work/d2j.err
  else
    return 2
  fi
  [ -s "$OUT" ]
}

if build_isf; then
  # vol3 scans -s dirs for ISFs and matches by kernel banner; offline the whole way.
  exec vol -q -s "$ISF_DIR" -f "$DUMP" "$PLUGIN" "$@"
else
  echo '##NEED## {"type":"tool_gap","reason":"no_kernel_symbols"}'
  echo "vol-linux-isf: no kernel symbol material (vmlinux+DWARF / System.map) in /input;" \
       "cannot build a Linux ISF offline. Falling back to strings." >&2
  strings -n 6 "$DUMP" || true
fi
