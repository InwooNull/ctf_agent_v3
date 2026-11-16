"""Cybench run aggregator -> per-category end-to-end table + SOTA context.

Reads the run ledger (one JSON object per line) and the public manifest, and prints the
headline the senior asked for: solved / total overall and per category, net vs file-only,
plus the published Cybench SOTA band for reference. Verdicts come ONLY from the sealed
verifier (solver/verifier.py) — a row is SOLVED iff the verifier returned solved=True.

  ledger line schema (store/cybench_run/results.jsonl):
    {"cid","title","category","net":bool,"verdict":"SOLVED|FAILED|BLOCKED",
     "flag":<only when SOLVED>,"evidence_exp_id":...,"diagnosis":...}

  python3 eval/cybench_report.py [ledger.jsonl]   (default store/cybench_run/results.jsonl)
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = PROJECT_ROOT / "arena" / "cybench" / "_manifest.json"
DEFAULT_LEDGER = PROJECT_ROOT / "store" / "cybench_run" / "results.jsonl"

# Published Cybench SOTA band (ICLR'25 paper + follow-ups), full-task unguided success.
# Context only — our harness/budget differ, so this frames the number, it is not a target.
SOTA_NOTE = ("Cybench published full-task (unguided) solve rates sit in the single digits to "
             "~low-teens % for frontier models; the hardest tasks (web/pwn exploitation) "
             "dominate the failures.")


def main():
    ledger = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LEDGER
    manifest = json.loads(MANIFEST.read_text())
    rows = {}
    if ledger.exists():
        for line in ledger.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            rows[r["cid"]] = r   # last write wins (re-runs supersede)

    by_cat = defaultdict(lambda: {"total": 0, "solved": 0, "done": 0})
    net_tot = net_solved = file_tot = file_solved = 0
    for cid, info in manifest.items():
        cat = info["category"]
        by_cat[cat]["total"] += 1
        r = rows.get(cid)
        solved = bool(r and r.get("verdict") == "SOLVED")
        if r:
            by_cat[cat]["done"] += 1
        if solved:
            by_cat[cat]["solved"] += 1
        if info["net"]:
            net_tot += 1; net_solved += int(solved)
        else:
            file_tot += 1; file_solved += int(solved)

    total = sum(c["total"] for c in by_cat.values())
    solved = sum(c["solved"] for c in by_cat.values())
    done = sum(c["done"] for c in by_cat.values())

    print("# Cybench end-to-end — our agent framework\n")
    print(f"**Overall: {solved}/{total} solved**  ({done}/{total} attempted so far)\n")
    print("| category | solved | total | attempted |")
    print("|---|---|---|---|")
    for cat in sorted(by_cat):
        c = by_cat[cat]
        print(f"| {cat} | {c['solved']} | {c['total']} | {c['done']} |")
    print(f"| **all** | **{solved}** | **{total}** | **{done}** |\n")
    print(f"- file-only: {file_solved}/{file_tot} solved")
    print(f"- networked (live target): {net_solved}/{net_tot} solved\n")
    print(f"> SOTA context: {SOTA_NOTE}")

    # honesty: list what is still pending
    pending = [cid for cid in manifest if cid not in rows]
    if pending:
        print(f"\n_{len(pending)} tasks not yet attempted._")


if __name__ == "__main__":
    main()
