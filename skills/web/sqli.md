# SQL injection — blind / boolean / time / error / union

**Signal.** A parameter, header, or cookie reaches a SQL query: a `'` triggers a SQL
error or a 500; the response differs for `1 AND 1=1` vs `1 AND 1=2`; a login form falls
to `' OR '1'='1`; a `SLEEP(5)`/`pg_sleep(5)`/`WAITFOR DELAY` measurably delays the
response.

**Precondition.** Your input is concatenated into SQL (not fully parameterised). Decide
which channel you have before choosing a technique:
- **error-based** — the app echoes DB error text → fastest; extract via error messages.
- **union-based** — the query's result is rendered and you can match column count/types
  (`ORDER BY n`, `UNION SELECT ...`) → pull data directly.
- **boolean-blind** — no output/no error, but the page *changes* with a true/false
  condition → infer data bit-by-bit from the differing response.
- **time-blind** — no output and no visible difference, but a conditional sleep delays
  the response → infer data from timing. Slowest; last resort.

**Procedure.**
1. Confirm injection manually first with `requests`: send `'`, `''`, `1 AND 1=1` /
   `1 AND 1=2`, and a sleep payload; note status, length, timing. This tells you the
   channel *and* proves it is worth sqlmap's budget.
2. Capture the exact injectable request (method, path, params, cookies, headers). For
   anything beyond a trivial GET param, save it to `/work/req.txt` and feed sqlmap `-r`.
3. Run sqlmap narrowly:
   `sqlmap -r /work/req.txt --batch --dbms=<guess> --technique=<BEUST subset>
   -p <param> --level 2 --risk 1` then escalate `--level/--risk` only if it finds the
   point but not the data. Add `--dump -T <table>` / `-D <db>` once you know the schema;
   `--sql-query` for a targeted read (e.g. the flag column).
4. The flag usually lives in a non-obvious table/column (`flag`, `secret`, a `users`
   row). Enumerate `--tables`/`--columns` before a blind full `--dump`.

**Tool.** `sqlmap` (present). Keep `--technique` tight to the channel you confirmed;
`--batch` for non-interactive; `--threads` modestly. A blind full-DB crawl will burn the
whole budget — target the one table you need.

**Failure signal → pivot.** sqlmap reports "not injectable" though your manual `'`
broke it → the param needs a different prefix/suffix or a cookie/header injection point
sqlmap did not try; set `--prefix/--suffix`, mark the point with `*`, or inject the
header/cookie explicitly. Everything 403/WAF-blocked → try `--tamper` sparingly, or a
smaller hand-built boolean oracle in `requests`. Second-order (input stored, fires on a
different page) → sqlmap's `--second-url`/`--second-req`.
