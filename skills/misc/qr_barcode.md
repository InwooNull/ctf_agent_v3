# QR / barcode decoding (zbar / pyzbar)

**When:** an image that is (or hides) a QR code, DataMatrix, or 1-D barcode
(Code128/EAN/UPC), or many small code images to batch-read. Also a QR given as ASCII
art / a matrix of characters — reconstruct it to a bitmap first.

**Procedure:**
- CLI: `zbarimg --raw image.png` (`--raw` prints just the payload, no type prefix).
- Python: `from pyzbar.pyzbar import decode; from PIL import Image;
  decode(Image.open('x.png'))` → list of results with `.data` and `.type`.

**When a decode fails — preprocess, don't give up:** most CTF QR failures are image
quality, not the decoder.
- **too small** → upscale (`convert in.png -scale 400% out.png`) — zbar needs enough
  pixels per module.
- **inverted / colored** → make it black-on-white: `convert in.png -threshold 50% out`
  or invert with `-negate`; try both polarities.
- **noisy / anti-aliased** → threshold to pure B/W; crop to just the code.
- **rotated / skewed** → rotate in 90° steps; zbar tolerates some skew but not heavy.
- **a QR drawn in text / a pixel matrix** → build the bitmap with Pillow (one module =
  N×N block), save a PNG, then decode.
- **partial / damaged** → QR has error correction; reconstruct the finder/timing
  patterns and let the decoder recover the rest.

**Failure signal → pivot:** zbarimg says "scanned 0 barcode symbols" after preprocessing
→ it may not be a standard symbology (custom 2-D grid → decode the matrix by hand), or
the payload is split across several codes (decode each, concatenate).

**Verify:** the decoded payload may itself be encoded (base64, another layer) — run it
through `encoding.md` and confirm the final flag before reporting.
