# SSRF & XXE — making the server fetch / parse for you

## SSRF (server-side request forgery)
**Signal.** The app fetches a URL you supply or influence: a `?url=`/`?img=`/`?webhook=`
param, a "fetch preview", a PDF/screenshot generator, an avatar-by-URL, or any feature
that reaches out. The flag is often behind a loopback-only admin/metadata endpoint the
*server* can reach but you cannot.

**Precondition.** Your value becomes the target of a server-side request. In this
environment the only network is loopback, so SSRF typically means reaching a service or
route bound to `127.0.0.1`/another port that the external interface does not expose, or
a `file://` read.

**Procedure.**
1. Confirm the fetch happens server-side (response reflects fetched content, or timing
   proves a request). Point it at a loopback endpoint you control to see the outbound
   request shape (headers, method).
2. Redirect it to the internal target: `http://127.0.0.1:<port>/admin`,
   `http://localhost/...`, or `file:///` for a local file read. Try alternate
   encodings/representations if a naive filter blocks `127.0.0.1` (decimal/hex IP,
   `[::1]`, a redirect you host, `0.0.0.0`).
3. Chain where needed: SSRF → internal admin API → flag; or SSRF `file://` → read the
   flag file / config.

## XXE (XML external entity)
**Signal.** The app parses XML you provide: a SOAP/XML API, an SVG/DOCX/XLSX upload
(these are XML inside), an RSS/XML config import.
**Precondition.** The parser resolves external entities (not hardened). Confirm with a
harmless internal entity first.
**Procedure.** Define a DOCTYPE with an external entity and reference it in a returned
field: `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///path/to/flag">]>` then use `&x;` where
the response echoes it. If the value is not echoed, use **blind/OOB XXE**: a parameter
entity that triggers an outbound fetch to a loopback endpoint you control, exfiltrating
the file in the request. PHP targets can use `php://filter/convert.base64-encode` to
read source.

**Tool.** No CLI — craft the XML/URL and send with `requests`. Build XML by hand or with
the stdlib; keep the entity payload minimal.

**Failure signal → pivot.** SSRF filter blocks localhost literals → try the encodings/
redirect above, or a different scheme (`gopher://` is usually unavailable here —
prefer `http`/`file`). XXE entity not resolved → parser hardened; pivot to blind/OOB, or
reconsider whether the upload is parsed as XML at all.
