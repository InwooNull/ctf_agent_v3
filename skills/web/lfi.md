# Local file inclusion / path traversal

**Signal.** A parameter names a file or path: `?file=`, `?page=`, `?lang=`, `?template=`,
`?download=`, an `include`/`require` driven by input, or a download endpoint that joins
your value to a directory. The flag is a file outside the web root (`/flag`,
`/etc/...`, the app's config, another user's file).

**Precondition.** Your value reaches a filesystem read/include with insufficient
normalisation. Confirm with a known-readable file before chasing the flag:
`../../../../etc/passwd` (or the app's own source) returning content proves traversal.

**Procedure.**
1. Probe traversal depth: increase `../` until a known file (`/etc/passwd`, or a file
   you saw in the source tree) comes back. Note any prefix/suffix the app adds (e.g. it
   appends `.php` → you may need a null-byte on ancient PHP, or a wrapper).
2. Read the flag file directly if you can locate it (`/flag`, `/flag.txt`, the path hinted
   by the app/source, env via `/proc/self/environ`).
3. **PHP wrappers**, when it is a PHP `include`:
   - `php://filter/convert.base64-encode/resource=index.php` → read source (then find
     the real bug / flag path) without executing it.
   - `php://input` / `data://` → if `include` executes your content, achieve RCE
     (depends on `allow_url_include`).
   - **log/session poisoning**: write a payload into a file the server controls (access
     log, session file, `/proc/self/environ` via User-Agent) then include it to execute.
4. Absolute paths sometimes work directly if no base dir is prepended — try both
   traversal and absolute.

**Tool.** No CLI — `requests`/`web_client`. For a source leak via `php://filter`,
base64-decode the result locally and read it to find the flag location or the next bug.

**Failure signal → pivot.** `../` stripped or normalised → try encoded (`%2e%2e%2f`,
double-encode, `....//`), a wrapper, or an absolute path. Read works but returns the
app's rendered page (it executed, not read) → use `php://filter` to get source instead
of execution. No file outside a jail readable → the goal may be reading app source to
find a different bug, not the flag directly.
