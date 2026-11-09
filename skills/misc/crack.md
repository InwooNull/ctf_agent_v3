# Cracking hashes & password-locked files (john; hashcat when justified)

**When:** a hash string (`$1$`, `$6$`, `$2y$`, raw MD5/SHA, NTLM), a `/etc/shadow`
line, or a password-protected zip/rar/7z/pdf/office/ssh-key whose password you must
recover. **No GPU here**, so john (CPU) is primary; hashcat is present but CPU-slow —
use it only for rule/mask patterns john handles clumsily, and prefer another path for a
large keyspace.

**Condition check first:** before cracking, ask whether you even need to. Is the hash a
known plaintext (reversible by lookup logic), is the "encryption" actually an encoding
(`encoding.md`), is the password visible in strings/metadata/a pcap? Cracking is the
*last* resort, not the first.

**Sandbox note (important — classic john):** the image ships *classic* John the Ripper
(not jumbo), which stores its pot/log/session under `$HOME/.john` and, unlike jumbo,
has **no `--pot` flag** and does **not auto-create** that dir. The container runs as a
uid with no passwd entry, so before calling john set `HOME` to the writable workdir and
make the dir yourself:
```python
import os, subprocess
os.environ["HOME"] = "/work"; os.makedirs("/work/.john", exist_ok=True)
env = {**os.environ, "HOME": "/work"}
subprocess.run(["john", "--wordlist=/work/w.txt", "/work/h.txt"], env=env)
subprocess.run(["john", "--show", "/work/h.txt"], env=env)   # same HOME for --show
```
Skip this and john dies with `.john/john.log: No such file or directory`.

**Procedure (locked file → hash → crack):**
1. Convert the locked file to a john hash with the matching `*2john` tool:
   `zip2john file.zip > h`, `pdf2john.pl file.pdf > h`, `rar2john`, `7z2john`,
   `ssh2john`, `office2john.py`. Inspect `h` to confirm the format was detected.
2. Crack: `john h` (uses john's default wordlist + rules), or point a wordlist:
   `john --wordlist=words.txt --rules h`. Show the result with `john --show h`.
3. For a bare hash, let john autodetect, or force: `john --format=raw-sha256 h`.
   List supported formats with `john --list=formats`.

**Attack strategy:**
- **wordlist + rules** (default) — by far the most productive for CTF passwords.
- **incremental / brute** — `john --incremental` only for short/known-charset keys.
- **mask** (known structure, e.g. `flag{6 lowercase}`) — `john --mask='?l?l?l?l?l?l'`
  or hashcat `-a 3`. Use when the keyspace is small and structured.
- **rule/mask hashcat** — `hashcat -m <mode> -a 0 h words.txt -r rule` **only** when the
  rule engine buys you something and the keyspace is CPU-feasible; otherwise stay on
  john. Pick `-m` from `hashcat --help | grep -i <algo>`.

**Failure signal → pivot:** nothing cracks within budget → the password is probably not
in a generic wordlist; look again for it leaking somewhere (metadata, a note, a pcap, a
memory dump), or reconsider whether cracking is even the intended path.

**Verify:** a cracked password/hash is only a step — use it to open the real artifact
and confirm the flag in-container before reporting.
