# Steganography (steghide / zsteg / outguess + Pillow/numpy)

**When:** a media file (PNG/BMP/JPG/WAV/GIF) that is suspiciously large for its visible
content, has stego-flavored hints, or is explicitly "find the hidden message". Always
do the cheap checks before the stego tools.

**Cheap checks first (do these every time):**
- `file`, `exiftool` (comments/metadata often hold the flag or a passphrase),
  `strings -n 8`, `binwalk` (appended/embedded data — see `archive.md`), and look at
  the image (`convert` to extract/alter).

**Tool by format:**
- **JPEG** → `steghide extract -sf img.jpg` (prompts for a passphrase; empty, or one
  found in metadata/the prompt). `outguess -r img.jpg out` as the alternative JPEG
  tool. steghide also handles BMP/WAV/AU.
- **PNG / BMP (lossless) LSB** → `zsteg -a img.png` (tries all LSB orderings/channels;
  `-a` = all). This is the go-to for PNG LSB and is **not** what steghide does.
- **WAV / audio** → `steghide` (if JPEG-style embed), or inspect the **spectrogram**
  (a flag drawn in frequency) — render it and read it.

**Custom LSB / bit-plane (when the tools find nothing):** many challenges use a
bespoke embedding. With Pillow+numpy:
- pull the LSB of each channel: `a = np.array(Image.open(p)); bits = a & 1` — then pack
  bits to bytes in row/col order, try each channel and both bit orders.
- view individual **bit planes** (plane 0..7) as images — a hidden layer often pops out.
- check the **alpha** channel and any palette; check for data **after** the image's end
  marker (`binwalk`).

**Passphrase hunt:** steghide/outguess need a passphrase — it is usually *given*
(filename, exif comment, the prompt, a sibling file). If truly unknown and short, a
wordlist attempt is possible but treat it as a last resort (`crack.md` mindset).

**Failure signal → pivot:** tools + LSB + bit-planes all empty → re-examine the family
assumption: maybe it's carving (`archive.md`), a QR hidden in the image
(`qr_barcode.md`), or the "image" is a disguised archive (`file` lied — check the magic
with `xxd | head`).

**Verify:** the extracted payload may be a further layer (`encoding.md`) — confirm the
final flag before reporting.
