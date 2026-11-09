# Server-side template injection (SSTI)

**Signal.** Input you control is rendered through a server-side template engine: a
math-probe like `{{7*7}}` (Jinja2/Twig), `${7*7}` (Freemarker/JSP EL), `<%= 7*7 %>`
(ERB), or `#{7*7}` comes back evaluated (`49`), or a template-engine stack trace leaks
from malformed input. Common in a "greeting"/"profile name"/"email template"/error page
that echoes your value.

**Precondition.** The value is used to *build* the template (concatenated into the
template string), not just passed as a rendered variable. Confirm by probing an
arithmetic/string expression for the engine family and seeing it evaluated. A value that
comes back literally (`{{7*7}}` stays `{{7*7}}`) is NOT SSTI.

**Procedure.**
1. Fingerprint the engine: try `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`,
   `{7*7}`. The one that yields `49` names the family (Jinja2/Twig/Freemarker/ERB/etc.).
2. Escalate within that family toward object/attribute access, then to the runtime:
   - **Jinja2 (Python/Flask)**: walk from a built-in object through `__class__` →
     `__mro__`/`__bases__` → `__subclasses__()` to reach an `os`/`subprocess`/file
     primitive, or use exposed globals (`config`, `request`, `lipsum`, `cycler`,
     `self`) as shortcuts. Read the flag file or run a command.
   - **Twig/Freemarker/Velocity/ERB**: use the family's known object-access/`exec`
     construct (e.g. Freemarker `freemarker.template.utility.Execute`).
3. Prefer the least-privileged action that gets the flag: read the flag file or env
   var directly rather than a full shell if that is all you need.

**Tool.** No CLI — build the payload and send it with `requests`/`web_client`. Iterate
the probe → attribute-walk → read, confirming each step's output before the next.

**Failure signal → pivot.** `{{7*7}}` echoes literally → not template-built input;
reconsider (maybe XSS/reflection, not SSTI). Evaluation works but object access is
filtered/sandboxed (e.g. a locked-down Jinja `SandboxedEnvironment`) → find an unbound
builtin the sandbox missed, or use an allowed global; if truly sealed, the intended bug
may be information disclosure (read `config`/env) rather than RCE.
