# Archives & carving (7z / unzip / binwalk / foremost)

**When:** a zip/7z/tar/gz, a firmware or filesystem blob, or any file that `file`/
`binwalk` says contains **other** files — including data appended after a valid image
(the classic "flag hidden after PNG IEND").

**Plain archives:** if `file` says it's a normal archive, just extract it —
`7z x file` (handles zip/7z/rar/tar/gz/xz/cab/… uniformly), `unzip`, `tar xf`. Don't
`binwalk -e` a plain zip; that's for *embedded/unknown* data.

**Nested / recursive:** CTF archives are often many layers deep or a quine-ish bomb of
renamed files. Extract one layer, `file *` the results, repeat. Watch for a huge decompressed size (a zip bomb — don't blindly fully extract; inspect the listing with
`7z l` first).

**Password-protected archive:** → `crack.md` (`zip2john`/`7z2john` → `john`). Check for
the password leaking elsewhere first.

**Carving (data embedded in / appended to another file):**
- `binwalk file` — scan for embedded signatures (what and at what offset).
- `binwalk -e file` — extract the found embedded files (into `_file.extracted/`).
  If binwalk's extraction misses something it listed, carve that offset manually:
  `dd if=file bs=1 skip=<offset> of=out`.
- `foremost -i file -o out/` — header/footer-based carving (good for images/docs in a
  raw blob or disk image when you know the types).
- appended data: `binwalk` shows the trailing offset; or find the format's end marker
  (`IEND` for PNG, etc.) with `xxd`/`grep -aboP` and slice after it with `dd`.

**Broken/truncated archive or bad header:** inspect magic bytes (`xxd | head`); a
single flipped/removed signature byte is a common trick — repair it (write the correct
magic back) and re-extract.

**Failure signal → pivot:** binwalk/foremost find nothing but the file is oversized →
it's probably LSB/metadata stego (`stego.md`), not carving.

**Verify:** confirm the extracted flag against the challenge oracle/format before report.
