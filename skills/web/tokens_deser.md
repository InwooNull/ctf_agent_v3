# Auth tokens & deserialization — JWT, signed cookies, native blobs

**Signal.** A token you hold decides who you are or what you may do: a JWT
(`eyJ...` three dot-separated b64url parts), a signed framework cookie (Flask
`session=...`, Rails/Express), or a serialized object blob — PHP (`a:`/`O:8:"..."`),
Python pickle, Java (`rO0AB`/magic `AC ED 00 05`), Ruby Marshal (`\x04\x08`), .NET
ViewState. You want to forge privilege (become admin, set `is_admin=1`) or trigger a
gadget chain.

## JWT
**Precondition.** The server trusts the token's claims and you can influence its
verification. Check, in order:
- **`alg:none`** — set header `alg` to `none`/`None`, drop the signature; works if the
  server accepts unsigned tokens.
- **algorithm confusion `RS256→HS256`** — if the public key is known/recoverable, sign
  an HS256 token using the PUBLIC key bytes as the HMAC secret; the server verifies
  RS256-as-HMAC with that key.
- **weak HMAC secret** — brute/guess a short `HS256` secret (a small wordlist) offline,
  then re-sign with elevated claims.
- **`kid` / `jku` / `x5u` abuse** — `kid` is a path/SQL sink (point it at a file whose
  contents you know, e.g. an empty/predictable key, or inject); `jku`/`x5u` point the
  server at a key set — host one on a loopback endpoint you control if the server
  fetches it.

**Procedure.** Decode header+payload (`base64`); identify the trust flaw above; forge
the token with the elevated claim (`"admin":true`, a different `sub`); send it; confirm
the privileged response. Use `PyJWT` or hand-roll with `hmac`/`hashlib`/`base64`.

## Native-object deserialization
**Precondition.** The app deserializes attacker-controlled bytes with an unsafe sink
(PHP `unserialize`, Python `pickle.loads`, Java `readObject`, Ruby `Marshal.load`,
.NET `BinaryFormatter`/ViewState). For RCE you need a usable gadget (a class whose
magic/deserialize method does something dangerous) present in the app.
**Procedure.** Identify the format from the magic bytes; craft an object that, on
deserialization, invokes the gadget (PHP POP chain via `__wakeup`/`__destruct`; Python
pickle `__reduce__`; Java via a known library gadget if that library is loaded). Prefer
the minimal effect that yields the flag (read a file / env) over a full shell.

**Tool.** No dedicated CLI — `requests` + the stdlib. Treat `pickle`/`Marshal` as
*analysis* targets; only build a payload for the specific sink the app exposes.

**Failure signal → pivot.** Forged JWT rejected → wrong trust flaw; re-check whether the
server really allows `none`, or whether the secret/key assumption is wrong. Deserialize
sink present but no gadget → the intended bug may be object-property injection (set a
field like `isAdmin`) rather than RCE; or a different endpoint deserializes.
