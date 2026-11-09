# Interpreter jails / sandbox escapes (knowledge, not a tool)

**When:** you interact with a prompt or `eval` that runs your input in Python / Bash /
Ruby but **filters** it (a blacklist of keywords, a char whitelist, an AST check, a
length cap) and you must reach code execution, a file read, or the flag. This is a
reasoning problem about the language's internals — no tool solves it; read the filter
exactly, then route around it.

**General method:** (1) read the filter's *mechanism* — substring blacklist vs. AST/
token check vs. char whitelist vs. attribute-access ban — because the bypass differs by
mechanism; (2) find a path to the capability that avoids the banned surface; (3) build
the forbidden strings/objects indirectly.

**Python (most common):**
- **reach builtins without naming them:** walk the object graph from a literal —
  `().__class__.__base__.__subclasses__()` to find a class whose methods give you
  `os`/`subprocess`/file I/O; or `type` / `__import__` via `__builtins__`.
- **build banned names as strings:** `getattr(obj, 'sy'+'stem')`, `chr()`/`\x`-escapes,
  `bytes.fromhex`, string concat/`join`, `%`/`.format` — defeats substring blacklists.
- **f-strings / format** can call `__getattr__`/index into objects (`{obj.__class__}`);
  `str.format` can traverse attributes/items on its arguments.
- **AST / keyword bans:** if `import`/`exec`/`()` call-syntax is blocked, reach the goal
  through operators, comprehensions, decorators, or `__getitem__` instead of a call;
  attribute access via `getattr`; dunder traversal instead of `import`.
- **char-whitelist jails** (only a few symbols allowed) — the classic all-`[]()!+`
  style — build any string from coercions; reserve for when the alphabet is truly tiny.
- **read the flag without RCE:** often `open('flag').read()` reached via the subclass
  walk is enough — don't over-engineer to a full shell.

**Bash jails:** bypass command/space/char filters with brace/`$IFS` for spaces,
globbing (`/???/c?t`), quoting/`$()`/backslashes to break up keywords, variable
indirection (`${PATH:0:1}` to build `/`), `$'\x..'`. Often `cat f*` beats a blocked
`cat flag`.

**Ruby jails:** `send`/`public_send` to call a method whose name is a built string,
`eval`/`instance_eval`, backticks or `%x{}` for shell, `Object.const_get` to reach a
constant/class, `__method__`/reflection to avoid literal keywords.

**Precedence / caution:** match the bypass to the *actual* filter mechanism — a bypass
for a substring blacklist does nothing against an AST whitelist. Enumerate the banned
surface first; don't spray payloads.

**Verify:** when the jail is remote/interactive, the flag is confirmed by the service
printing it in response to your payload — that printout IS the run-to-win. Don't report
a flag you only *expect* the payload to produce.
