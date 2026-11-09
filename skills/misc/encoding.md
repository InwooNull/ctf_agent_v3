# Encodings & esolangs (recognise, then decode)

**When:** text/bytes that are "almost" readable or obviously transformed, and the task
is to decode rather than break crypto. The skill is **recognition** — identify the
scheme from its shape, then decoding is mechanical (stdlib does almost all of it).

**Recognise by shape:**
- **base64** — `[A-Za-z0-9+/]`, length ≈ multiple of 4, maybe `=` padding. `base64`
  variants: `-` `_` → urlsafe; all-caps+digits+`=` → likely **base32**; `~` present or
  a leading `<~` → **base85/ascii85**.
- **hex** — only `[0-9a-f]`, even length. **decimal/octal/binary** — groups of digits;
  binary = runs of `01` in bytes of 8.
- **URL-encoding** `%XX`; **HTML entities** `&#..;`; **punycode** `xn--`.
- **ROT/Caesar** — looks like English with shifted letters (try all 25; ROT13 is the
  usual); **Atbash** — reversed alphabet.
- **Morse** — `. - / ` groups; **Bacon** — groups of 5 A/B (or two fonts/cases encoding
  a binary); **tap code**, **A1Z26** (numbers 1–26 = letters).
- **Gray code** — a bitstring where consecutive values differ by one bit; convert
  Gray→binary (`b_i = g_i XOR b_{i-1}` from the MSB) then read as bits/bytes.
- **esolang source** — Brainfuck (`+-<>[].,`), Ook (`Ook. Ook?`), Malbolge, Whitespace
  (only space/tab/newline), Piet (an image of color blocks). Recognise, then interpret.

**Procedure:**
1. Identify the layer from its alphabet/shape (above). When unsure, try the cheap ones
   first (base64/hex/base32) and see if the output becomes readable or another known
   layer.
2. Decode with Python stdlib: `base64` (b64/b32/b85/a85), `binascii`, `codecs`
   (rot13, hex), `urllib.parse.unquote`, `html.unescape`. For Morse/Bacon/A1Z26/Gray/
   Brainfuck write the tiny mapping/interpreter by hand — they are a few lines.
3. **Layers compound:** CTF encoding chains are often base64→hex→gzip→… Decode one
   layer, re-inspect the output's shape, repeat until you hit the flag or real bytes.
   `file`/`strings` the intermediate bytes to catch a gzip/zlib/image boundary.

**Failure signal → pivot:** output never becomes readable after a couple of layers and
has high entropy / no structure → it's probably **encryption**, not encoding — this is
a crypto problem, not a misc decode. Stop layering and reconsider the family.

**Verify:** confirm the final decoded flag's format/oracle before reporting.
