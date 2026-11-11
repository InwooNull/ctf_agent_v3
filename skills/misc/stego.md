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

**Bespoke spatial / carrier-warp (when EVERY standard tool fails on a structured image):**
if `file`/`exiftool`/`strings`/`binwalk`, `zsteg -a`, LSB, bit-planes, palette/alpha, and
spectrogram all come up empty, but the image clearly *carries structure* (it is not random
noise — you see streaks, bands, or a regular pattern), stop bit-level hunting and suspect a
**geometric** encoding. The shape: a visible **carrier** layer (a distinct colour / channel
/ mark-set with *deterministic* regularity — e.g. a constant number of marks per column or
row) encodes the **parameter** of a transform applied to a scrambled **data** layer (a
per-column/row circular shift/roll, a rotation, an interleave, a permutation). The data
looks warped *because* each line was shifted by its own amount.
- Tells: a colour that recurs in a regular / constant-count pattern; data that reads as
  vertical (or horizontal) **streaks** (each column/row shifted independently); a name
  hinting *adjust / shift / shuffle / roll / scramble*.
- Recovery (Pillow+numpy): split layers by colour mask; read the per-line parameter off the
  carrier (e.g. the top-most carrier-mark `y` per column, or its mark count); invert the
  transform on the data layer (`np.roll(col, -offset)` per column, or `argsort` to undo a
  permutation); a light Gaussian blur sharpens anti-aliased marks into readable text.
- Budget: this is reasoning-heavy, not a tool you can spray. If 2–3 standard passes fail on
  a *structured* image, pivot to the carrier hypothesis **early** rather than exhausting the
  whole budget on bit-level tools.

**Passphrase hunt:** steghide/outguess need a passphrase — it is usually *given*
(filename, exif comment, the prompt, a sibling file). If truly unknown and short, a
wordlist attempt is possible but treat it as a last resort (`crack.md` mindset).

**Failure signal → pivot:** tools + LSB + bit-planes all empty → re-examine the family
assumption: if the image is *structured* (streaks/bands/a regular pattern), suspect a
**bespoke spatial / carrier-warp** encoding (see above) before anything else; otherwise
maybe it's carving (`archive.md`), a QR hidden in the image (`qr_barcode.md`), or the
"image" is a disguised archive (`file` lied — check the magic with `xxd | head`).

**Verify:** the extracted payload may be a further layer (`encoding.md`) — confirm the
final flag before reporting.
