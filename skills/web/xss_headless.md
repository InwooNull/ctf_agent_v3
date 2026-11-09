# XSS / client-side — and when you need a headless browser

**Signal.** Your input is reflected into HTML/JS, or stored and later shown to another
user, or the app says "an admin/moderator will review/visit" and takes a URL or a field
from you. The flag is often in the victim's cookie, localStorage, or a page only the
admin can reach.

**Precondition — do you actually need a browser?** Decide before launching chromium:
- **No browser needed** (prefer this): the "victim" is a server-side bot you can
  satisfy with a plain request, OR the exploit just needs to exfiltrate to an endpoint
  you can hit yourself, OR the reflection is server-rendered and you can read the result
  with `requests`. Many "XSS" challenges reduce to a `requests` call.
- **Browser needed**: the payload must execute real JS in a DOM (DOM-clobbering,
  `document.cookie`, a client-side router/template, a framework sink), or an admin bot
  genuinely renders your URL and you must observe what its JS does.

**Procedure (headless).**
1. Find the sink and the context (HTML body / attribute / JS string / URL). Build the
   minimal payload that escapes that context — test the reflection with `requests`
   first to see exactly how your bytes come back.
2. If a bot visits your URL, host the payload where the app expects (a stored field, or
   a param) and point the bot at it; the bot carries the privileged cookie/session.
3. Drive chromium with playwright to *be* the victim or to confirm execution:
   `with sync_playwright() as pw: b = pw.chromium.launch(args=["--no-sandbox"]); pg =
   b.new_page(); pg.goto(url); ...` then read `pg.content()`, `pg.evaluate(...)`,
   `pg.context.cookies()`. `--no-sandbox` is REQUIRED under the sandbox uid.
4. Exfiltrate to a loopback endpoint you control within the app, or read the DOM/cookie
   directly from the page object, and recover the flag.

**Tool.** `playwright` + `chromium`, **best-effort in this image**. Before relying on
it, check it is really present:
`python3 -c "from playwright.sync_api import sync_playwright" ` and read
`/opt/ctfagent/playwright_status.txt`. If it says chromium did not install, do NOT burn
budget retrying — fall back to the `requests`-level solve above.

**Failure signal → pivot.** `chromium.launch` hangs or dies (missing lib / sandbox) →
add `--no-sandbox --disable-dev-shm-usage`; if still failing, treat the headless lane as
unavailable and solve server-side. CSP blocks inline JS → move to a `src`/event-handler
vector the CSP allows, or a DOM sink that does not need inline script. Payload reflected
but not executing → wrong context escaping; re-read how the bytes come back.
