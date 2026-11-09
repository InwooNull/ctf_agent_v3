# Prototype pollution (JS / Node)

**Signal.** A Node/JavaScript app merges attacker-controlled JSON/query into an object:
a config/settings endpoint, a `deepmerge`/`extend`/`Object.assign`-style recursive
merge, a query-string parser that builds nested objects, or any "update profile with
this JSON" feature. You can set a key like `__proto__`, `constructor`, or
`prototype`.

**Precondition.** The merge/assignment does not guard against polluting
`Object.prototype`. Confirm by sending a property via `__proto__` and seeing it appear
on an unrelated object (a response field you did not set shows your injected value), or
a behaviour flip (a default-off flag becomes on for everyone).

**Procedure.**
1. Find the sink: a JSON body or query that reaches a recursive merge. Try
   `{"__proto__":{"polluted":"yes"}}` or `?__proto__[polluted]=yes` and check whether
   `polluted` leaks onto other objects/responses.
2. Pollute a property the app *reads* for a security decision: `isAdmin`, `role`,
   `authenticated`, a template option, or a flag the app checks with `obj.x` where `x`
   is normally undefined (so it falls through to the polluted prototype).
3. Chain to impact: an auth/role flip that reveals the flag; or a **gadget** — pollute a
   property that a downstream library reads to reach RCE/SSTI (e.g. a template engine
   option, a child-process option). The specific gadget depends on the libraries the
   app loads.
4. Note pollution is global and sticky for the process — a flip may affect the next
   request; use that where the flag is behind an admin-only path.

**Tool.** No CLI — `requests`/`web_client` with JSON bodies. Build the payload by hand;
verify the polluted property surfaced before building the chain.

**Failure signal → pivot.** `__proto__` stripped/ignored → try `constructor.prototype.x`
as the path, or an alternate parser quirk (array vs object, bracket vs dot). Pollution
confirmed but no security property reads it → hunt for a property an actual decision or
a loaded library consumes; without such a sink, pollution alone is not the flag path.
