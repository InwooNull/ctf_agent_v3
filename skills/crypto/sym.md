# Symmetric-cipher attacks (condition → principle → skeleton → failure → tool)

These are mostly solved with our own python + pycryptodome; no specialist tool needed.
The win is recognizing the MODE and its misuse from the observations.

## ECB detection and byte-at-a-time decryption
Condition: encryption is ECB (two identical plaintext blocks produce two identical
ciphertext blocks) AND you can control some plaintext that is concatenated with a secret
(`enc(prefix || your_input || secret)`).
Detect: send ≥2 blocks of a repeated byte; if adjacent ciphertext blocks repeat → ECB.
Principle: align so one unknown secret byte sits at a block boundary; brute that single
byte by matching the target block against enc(known||guess). Repeat, shifting by one.
Failure signal: no repeated blocks even with long constant input → not ECB (or there's a
random prefix of unknown length — first recover that length, then proceed).

## ECB cut-and-paste
Condition: ECB, and structured plaintext (e.g. `user=...&role=user`) whose field you want
to forge, with block-aligned control of the input.
Principle: ECB has no inter-block diffusion — rearrange whole ciphertext blocks to splice
an attacker-crafted block (e.g. one encrypting `admin\x0b…`) into the role position.

## CBC bit-flipping
Condition: CBC, you can modify ciphertext, and a plaintext bit/byte you want to change is
one full block AFTER a block you may corrupt.
Principle: P_i = D(C_i) XOR C_{i-1}. Flipping a byte of C_{i-1} flips the same byte of the
decrypted P_i (while garbling P_{i-1}). Use the IV to target the first block.

## CBC padding oracle
Condition: CBC AND an oracle that tells you (directly or via timing/error/behavior)
whether decryption produced valid PKCS#7 padding. Usually interactive.
Principle: for each block, recover D(C_i) byte-by-byte from the end by forging the
previous block so the plaintext ends in valid padding 0x01, then 0x02 0x02, … ; then
P_i = D(C_i) XOR real C_{i-1}. Also lets you ENCRYPT chosen plaintext.
Failure signal: the oracle's valid/invalid signal is noisy or absent → it isn't a padding
oracle; look for a different distinguisher.

## Stream / CTR / OTP key or nonce reuse
Condition: two ciphertexts encrypted with the SAME keystream (reused nonce in CTR, reused
key in a stream cipher / one-time pad).
Principle: C1 XOR C2 = P1 XOR P2 — the key cancels. Crib-drag a probable word (e.g.
"flag{", spaces) across the XOR; where it yields readable text in the other plaintext,
you've aligned it. Extend until both plaintexts emerge.
Failure signal: crib-dragging never yields readable text → nonces weren't actually reused,
or it's not a simple XOR stream.

## XOR with a short/repeating key
Condition: ciphertext = plaintext XOR (repeating key of length L).
Principle: single-byte key → try all 256, score by English/flag-charset frequency.
Repeating key → find L (Hamming-distance / Kasiski), then solve each column as single-byte.
Tool: plain python; `pycryptodome` for the actual ciphers when you need to re-encrypt.
