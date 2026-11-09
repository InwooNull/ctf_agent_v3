# Disk / filesystem forensics (The Sleuth Kit)

**When:** `file` reports a partition table (DOS/GPT), a filesystem (NTFS/FAT/ext/HFS),
or the artifact is a `.dd/.img/.raw/.e01` disk image and you need a **deleted file**,
file **slack**, a specific path's content, or the full directory tree. For a plain
mountable image where you just want visible files, `7z x` / loop-mount logic is simpler
— reach for TSK when files are deleted or the structure matters.

**Procedure:**
1. `mmls image` — list partitions and their **starting sector offsets**. Note the
   offset of the partition you want.
2. `fsstat -o <offset> image` — confirm the filesystem type and parameters.
3. `fls -o <offset> -r -p image` — recursive listing **including deleted entries**
   (deleted inodes are marked `*`). The leading number is the inode.
   - `-d` restricts to deleted entries only.
4. `icat -o <offset> image <inode> > out` — extract one file (deleted or live) by inode.
5. `tsk_recover -o <offset> image outdir/` — bulk-recover all (add `-e` for every inode
   incl. deleted/unallocated). Fast way to dump everything, then triage with `file`/
   `strings` in `outdir/`.

**Notes / traps:**
- Always pass the right `-o <offset>` (in sectors) — running TSK on the whole image
  instead of the partition is the most common mistake and yields "cannot determine file
  system type".
- The flag often lives in a **deleted** file, in **unallocated** space (carve with
  `foremost`/`binwalk` — see `archive.md`), or in an alternate data stream / slack.
- For a raw partition with no table, skip `mmls` and run `fls`/`fsstat` at offset 0.

**Failure signal → pivot:** "Cannot determine file system type" → wrong offset, or it's
not a filesystem but a carving target → switch to `foremost`/`binwalk` (`archive.md`).

**Verify:** confirm any recovered flag against the challenge oracle/format before report.
