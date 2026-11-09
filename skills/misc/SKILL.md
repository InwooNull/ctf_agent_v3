# Misc / Forensics cheat-sheet (C1 knowledge pack) — router

Knowledge only, in our own words: *which* technique fits *which* observation, the
condition that must hold for it to work, and *which tool* to reach for. It names no
challenge and contains no ready solution — you still derive and run everything
in-container, with the same budget/isolation as C0 (`--network none`).

This is a capability-insurance layer. "Misc" is a grab-bag: the hard part is usually
*identifying what kind of problem you are looking at* from the artifact, not the
mechanics once you know. On easy challenges you will (and should) just solve it
directly. Load a detail file only when a signal below matches — never load everything.

## How to use (identify first; do NOT blindly run tools)
1. `info` + inspect the artifacts first. Run `file *` on everything, `exiftool` on
   media, `strings -n 8` for obvious flags/markers, and note the sizes/types. Most of
   the work is deciding **which family** the challenge is in.
2. Match the dominant signal below to a technique family, open ONE detail file for the
   condition + procedure + the failure signal + which tool.
3. Confirm the precondition BEFORE running a heavy tool (e.g. don't launch a full
   `john` crack if the hash is a known-plaintext you can reverse, don't `binwalk -e` a
   file that `file` says is already a plain zip — just unzip it). A wrong-family tool is
   budget you will not get back.
4. If an attempt's failure signal fires, PIVOT to the alternative the detail file names
   rather than retrying the same thing.

## Technique router (signal → family → file)
- **a memory dump** (`file` says "data" and it is large/round-sized; name like
  `*.raw/.mem/.vmem/.dmp/.lime`; strings show OS artifacts, process names, registry
  paths) → **memory forensics** with volatility3 → `memory.md`
- **a disk / filesystem image** (`file` says a partition table, NTFS/FAT/ext, or a
  `.dd/.img/.e01`; you need deleted files, slack, or a specific path) → **disk
  forensics** with The Sleuth Kit → `disk.md`
- **a hash or a password-protected file** (a `$...$` hash string, `/etc/shadow`-style
  line, a password-locked zip/pdf/office, an encrypted file whose key is a weak
  password) → **cracking** with john (hashcat for rule/mask when justified) → `crack.md`
- **an image that may carry a QR / barcode**, or you must *read* a code → **QR/barcode
  decode** with zbar / pyzbar → `qr_barcode.md`
- **a packet capture** (`.pcap/.pcapng`) → **network forensics** with tshark →
  `pcap.md`
- **a media file with a hidden payload** (a suspiciously large PNG/JPG/WAV/BMP, stego
  hints, an odd LSB/alpha/spectrogram, a `steghide` passphrase lying around) →
  **steganography** → `stego.md`
- **a container / archive / carving target** (a zip/7z/tar, an embedded blob, a
  firmware/filesystem dump, trailing data after an image) → **archive & carving** →
  `archive.md`
- **a "jail" / sandboxed interpreter** you interact with (a Python/Bash/Ruby prompt or
  eval that filters your input) → **escape by language internals**, not a tool →
  `jail.md`
- **unknown text / bytes that are "almost" readable** (base-N, a cipher-looking blob,
  brainfuck, esolang, Gray code, Morse, a QR-as-text) → **encoding & esolang** →
  `encoding.md`

## Tools in this image  [ctfagent-misc:0.3, runtime `--network none`]
Signal router above tells you *which family*; reach for the matching tool only after
the precondition holds. All work offline (the only build-time-net dependency, vol3's OS
symbol tables, is **bundled into the image**, so volatility3 runs fully offline).

- **memory dump** → `volatility3` (`vol`/`vol3`). Windows **and** Linux/Mac symbol ISF
  packs are baked in, so `windows.*`, `linux.*`, `mac.*` plugins run with `--network
  none`. See `memory.md`.
- **disk / filesystem image** → The Sleuth Kit (`sleuthkit`): `mmls` (partitions), `fls` (list incl.
  deleted), `icat` (extract by inode), `fsstat`, `tsk_recover` (bulk recover). See
  `disk.md`.
- **hashes / password-locked files** → `john` (CPU; primary here — no GPU). Companion
  `*2john` tools (`zip2john`, `pdf2john.pl`, `rar2john`, `ssh2john`, …) turn a locked
  file into a crackable hash. `hashcat` is present too **but GPU-less = CPU-slow**: use
  it only for rule/mask attacks john is clumsy at, and prefer john/another path for a
  large keyspace. See `crack.md`.
- **QR / barcode** → `zbarimg` (CLI) or `pyzbar` (Python, already in 0.2) over a
  Pillow/`convert`-preprocessed image. See `qr_barcode.md`.
- **pcap** → `tshark` (filters, `-T fields` extraction, `--export-objects`,
  `follow`). See `pcap.md`.
- **stego** → `steghide` (JPEG/BMP/WAV/AU, passphrase), `zsteg` (PNG/BMP LSB),
  `outguess` (JPEG), plus Pillow/numpy for custom LSB/bit-plane/alpha work. See
  `stego.md`.
- **archive / carving** → `7z`, `unzip`, `binwalk` (scan/`-e` extract), `foremost`
  (header-based carving). See `archive.md`.
- **general** → `file`, `exiftool`, `strings`, `xxd`, `pdftotext`, ImageMagick
  (`convert`), `numpy`/`pillow` — reach for these in step 1 before anything heavy.

Precedence: identify the family from the signal router, pick the matching tool, confirm
the precondition, use the tool for the mechanical step, and **verify the flag against
the challenge's own oracle (or a clear evidence chain) in-container before reporting** —
a found-looking string is not a flag until something confirms it.
