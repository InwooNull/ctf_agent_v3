"""Audit C0 solver-agent transcripts: every tool call must be a c0_cli.py call
for that agent's own run id (the final hand-back message is allowed).

  python3 eval/c0_transcript_audit.py <rep> <transcript.jsonl> [...]  > store/c0/audit_r<rep>.json

Prints per-transcript counts and any non-conforming call (first line only).
Transcripts are the harness's subagent JSONL files; this script only reads them.
"""
import json
import re
import sys

ALLOWED = re.compile(r"^cd ~/ctf_agent_v3 && python3 eval/c0_cli.py (c0-p5_[0-9a-f]{6}-r(\d+)) "
                     r"(info|exp|report|give_up|status)\b")
FORBIDDEN_SUBSTR = ("scorer_keys", "make_dev", "manifest.json", "store/")


def audit(path, rep):
    calls, bad, run_ids = 0, [], set()
    for line in open(path, encoding="utf-8"):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        content = (rec.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            if b.get("type") != "tool_use" or b.get("name") == "SubagentHandback":
                continue
            calls += 1
            inp = b.get("input", {})
            cmd = inp.get("command", "")
            first = cmd.splitlines()[0] if cmd else json.dumps(inp)[:200]
            m = ALLOWED.match(first) if b.get("name") == "Bash" else None
            # anything after the heredoc body is still shell; check the command's non-code lines
            tail_ok = not cmd or cmd.rstrip().endswith("EOF") or "\n" not in cmd
            if m and int(m.group(2)) == rep and tail_ok and not any(s in first for s in FORBIDDEN_SUBSTR):
                run_ids.add(m.group(1))
            else:
                bad.append({"tool": b.get("name"), "first_line": first[:200]})
    return {"transcript": path, "tool_calls": calls, "run_ids": sorted(run_ids),
            "nonconforming": bad, "clean": not bad and len(run_ids) == 1}


def main(argv):
    rep = int(argv[0])
    res = [audit(p, rep) for p in argv[1:]]
    print(json.dumps({"rep": rep, "all_clean": all(r["clean"] for r in res),
                      "runs_covered": sorted(i for r in res for i in r["run_ids"]),
                      "transcripts": res}, indent=1))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
