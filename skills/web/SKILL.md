# Web exploitation cheat-sheet (C1 knowledge pack) — router

Knowledge only, in our own words: *which* bug class fits *which* observation, the
precondition that must hold for it to be exploitable, and *which tool or procedure* to
reach for. It names no challenge and contains no ready exploit — you still find the bug
and run everything in-container, on the 2-uid web-service boundary, with the same
budget/isolation as C0 (`--network none`, the target reachable only on
`http://127.0.0.1:$PORT`).

This is a capability-insurance layer. The target is a live app; the flag lives
server-side (a DB row, a file outside the web root, another user's session) and is
reachable **only** by exploiting the app over HTTP — you cannot read it directly. The
hard part is usually *identifying the bug class* from the app's behaviour, not the
mechanics once you know. On easy challenges you will (and should) just solve it with
`requests`/`WebClient` directly. Load a detail file only when a signal below matches —
never load everything.

## How to use (identify first; do NOT blindly fire tools)
1. **Map the app first.** `info` for the card, then with `requests`/`WebClient` fetch
   `/`, note status codes, headers (`Server`, `Set-Cookie`, `X-Powered-By`, CSP),
   cookies (is a session a signed token? a JWT?), forms, and visible parameters. Pull
   `robots.txt`, `/sitemap.xml`, obvious files. If the public source tree is given
   (`/input/tree`), read it — the bug is usually visible there.
2. **Match the dominant signal** below to a bug class, open ONE detail file for its
   precondition + procedure + failure signal + the tool/approach.
3. **Confirm the precondition BEFORE launching a heavy tool.** A single reflected
   parameter you can read by hand does not need sqlmap; a static server with no JS does
   not need a headless browser. A wrong-class tool is budget you will not get back.
4. **If the failure signal fires, PIVOT** to the alternative the detail file names
   rather than retrying the same payload.

## Technique router (signal → bug class → file)
- **a parameter/header/cookie reaches a SQL query** (an error leaks SQL; a numeric/row
  response changes with `'`, `1 AND 1=1` vs `1 AND 1=2`; login bypass; a time delay on
  `SLEEP`/`pg_sleep`) → **SQL injection** (blind/boolean/time/error/union) → `sqli.md`
  → tool: **sqlmap**
- **your input is reflected into HTML/JS, or stored and shown to an admin, or an
  "admin/report bot" visits a URL you supply** (a contact/report form, "an admin will
  review") → **XSS / client-side**; if it needs a real DOM or a bot to execute JS →
  **headless browser** → `xss_headless.md` → tool: **playwright + chromium**
- **you need to discover hidden routes, files, or parameter names** (a sparse app,
  `/admin` 403, backup/`.git`/`.bak` files, a param that changes behaviour) →
  **content/parameter discovery** → `fuzzing.md` → tool: **ffuf**
- **a template engine evaluates your input** (`{{7*7}}`→`49`, Jinja2/Twig/Freemarker
  error, a "name"/"greeting" echoed through a template) → **SSTI** → `ssti.md`
- **a signed/opaque token you control is deserialized or verified** — a JWT (`eyJ...`),
  a language-native blob (PHP `O:`, Python pickle, Java `rO0`/`AC ED`, Ruby, .NET
  ViewState), a Rails/Express/Flask cookie → **auth-token & deserialization**
  (`alg:none`, `kid`/`jku` abuse, weak HMAC secret, gadget chains) → `tokens_deser.md`
- **the server fetches a URL you supply, or an XML/SVG/DOCX parser takes your input** →
  **SSRF / XXE** (reach loopback-only admin, `file://`, metadata; XML external
  entities, OOB) → `ssrf_xxe.md`
- **a filename/path parameter** (`?file=`, `?page=`, `?lang=`, `include`) → **LFI /
  path traversal** (`../`, PHP wrappers, log/session poisoning to RCE) → `lfi.md`
- **you can set object keys / merge JSON into an object** (a Node/JS app, a `__proto__`
  or `constructor.prototype` sink, a config/merge endpoint) → **prototype pollution** →
  `proto_pollution.md`

## Tools in this image  [ctfagent-web:0.3, runtime `--network none`, target on loopback]
The signal router tells you *which bug class*; reach for the matching tool only after
the precondition holds. Everything talks to `http://127.0.0.1:$PORT` only — there is no
other network. Your experiment is python run as the agent uid; it may `import requests`
/ `web_client` or subprocess any CLI below.

- **SQL injection** → **sqlmap** (`sqlmap -u <url> --batch ...`). Point it at the exact
  injectable request (use `-r reqfile` for a captured POST/cookie). Prefer a tight
  `--technique`, `--dbms`, and `--level/--risk` you justified over a blind full crawl —
  budget. For a quick manual check, `requests` with `'`/boolean/time payloads first.
  See `sqli.md`.
- **DOM XSS / JS-rendered / admin-bot** → **playwright** driving headless **chromium**
  (`chromium.launch(args=["--no-sandbox"])` — required under the sandbox uid). Use it to
  execute the page's JS, act as the victim/admin bot that visits your payload URL, and
  read the DOM/cookie the exploit produces. BEST-EFFORT: chromium may be absent in this
  image (heavy download) — if `playwright` import or `chromium.launch` fails, check
  `/opt/ctfagent/playwright_status.txt` and fall back to a `requests`-level solve (many
  "XSS" challenges exfiltrate to an endpoint you can hit directly). See
  `xss_headless.md`.
- **content/parameter discovery** → **ffuf** (`ffuf -u http://127.0.0.1:$PORT/FUZZ -w
  <wordlist> -mc 200,301,302,403 -s`). Fuzz paths, vhosts, or `?FUZZ=` params. There is
  no network, so bring/build your own small wordlist in `/work` (a few dozen likely
  names beats a giant list you cannot justify on budget). See `fuzzing.md`.
- **everything else** (SSTI, JWT/deserialization, SSRF/XXE, LFI, prototype pollution) →
  **procedure + `requests`/`web_client`**, no dedicated CLI needed. The detail file
  gives the detector, the precondition, and the request sequence; you build the payload
  and send it with python. `PyJWT` / the stdlib (`base64`, `hmac`, `hashlib`, `pickle`
  for analysis only) cover token work.

Precedence: map the app, read the signal router, pick the bug class, confirm its
precondition, use the tool/procedure for the mechanical step, and **verify the flag by
making the live app disclose it in-container before reporting** — a reflected or
guessed-looking string is NOT a flag until the target itself (or a clear in-container
evidence chain) produces it. Never `report` a flag you only pattern-matched; give up
cleanly instead of guessing.
