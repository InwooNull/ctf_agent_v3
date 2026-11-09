# Content & parameter discovery — ffuf

**Signal.** The app is sparse or hints at hidden surface: a bare `/`, an `/admin` that
403s, references to backup/debug/old files, a parameter whose name you must guess, or a
vhost-routed app. You need to find routes/files/params that are not linked.

**Precondition.** There is unlinked surface worth finding (not every challenge has it —
if the bug is in the one visible form, skip this). You have, or can build, a small
wordlist of *plausible* names — there is no network, so you cannot pull a 100k-entry
list; a few dozen well-chosen names (`admin`, `backup`, `config`, `.git/HEAD`, `api`,
`debug`, `flag`, `robots.txt`, `s3cr3t`, framework defaults) usually beats brute volume.

**Procedure.**
1. Build `/work/words.txt` from names justified by the stack you fingerprinted (PHP →
   `.php`/`config.php`/`phpinfo.php`; Flask → `/static`, `/console`; a `.git` hint →
   `.git/HEAD`, `.git/config`).
2. Path discovery:
   `ffuf -u http://127.0.0.1:$PORT/FUZZ -w /work/words.txt -mc 200,301,302,403 -s`
   (`-s` = quiet, prints only hits). Filter noise with `-fc 404` or `-fs <size>` when a
   catch-all returns 200 for everything.
3. Parameter discovery:
   `ffuf -u 'http://127.0.0.1:$PORT/page?FUZZ=1' -w /work/params.txt -fs <baseline>` —
   a changed response size/code for a param name reveals a hidden parameter.
4. Extensions/recursion only when justified (`-e .php,.bak,.txt`, `-recursion
   -recursion-depth 1`) — each multiplies requests and budget.

**Tool.** `ffuf` (present; fast static Go binary). Keep the wordlist small and the
matchers tight. Confirm each hit with a direct `requests` fetch before building on it —
ffuf tells you a path exists, not what it does.

**Sandbox quirk.** ffuf's scraper reads `$HOME/.config/ffuf`; the sandbox uid has
`HOME=/nonexistent`, so ffuf aborts with `open /nonexistent/.config/ffuf/scraper: no
such file or directory` BEFORE it fuzzes. Set `HOME=/work` (and `mkdir -p
/work/.config/ffuf`) in your experiment first — then it runs normally.

**Failure signal → pivot.** Everything returns 200/same size → a catch-all; set `-fs`
to that size or `-fc` appropriately so real hits stand out. Nothing found with a
generic list → the names are app-specific; mine them from the source tree, JS files,
comments, or error messages instead of fuzzing blind. 403 on a found path → that is
often the target: pivot to auth bypass / path-normalisation, not more fuzzing.
