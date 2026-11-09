# Network forensics (tshark)

**When:** a `.pcap/.pcapng`. Goal is usually to reconstruct a conversation, extract a
transferred file, or find a credential/flag inside traffic.

**Orient first:**
- `tshark -r cap.pcap -q -z io,phs` — protocol hierarchy: what is actually in here.
- `tshark -r cap.pcap -q -z conv,tcp` — conversations (who talks to whom, volumes).

**Extract:**
- **follow a stream:** `tshark -r cap -q -z follow,tcp,ascii,<n>` (stream index from
  the conversation list) — reconstructs one TCP session.
- **pull fields:** `tshark -r cap -Y '<display filter>' -T fields -e <field>` — e.g.
  `-Y http.request -e http.host -e http.request.uri`, or `-e urlencoded-form.value`.
- **carve transferred files:** `tshark -r cap --export-objects http,outdir/` (also
  `smb`, `tftp`, `imf`, `dicom`). Then triage `outdir/` with `file`/`strings`.
- **credentials / tokens:** filter the auth protocol (`-Y 'http.authorization'`,
  `ftp`, `telnet`, `-Y 'http.cookie'`).

**Common CTF shapes:**
- data smuggled in **DNS** queries → `-Y dns -T fields -e dns.qry.name`, then strip the
  domain suffix and decode the labels (often hex/base32 → `encoding.md`).
- data in **ICMP** payloads → `-Y icmp -T fields -e data.data`.
- a file split across packets → follow the stream or `--export-objects`, don't eyeball.
- **TLS** traffic → need the key/`SSLKEYLOGFILE` from the challenge materials to decrypt
  (`-o tls.keylog_file:keys.log`); without it the payload is opaque — look elsewhere.

**Failure signal → pivot:** the interesting bytes are encrypted/opaque and no key is
provided → the key or the real artifact is elsewhere in the challenge (a file, another
protocol); re-read the prompt for what you were actually meant to recover.

**Verify:** confirm the extracted flag/format in-container before reporting.
