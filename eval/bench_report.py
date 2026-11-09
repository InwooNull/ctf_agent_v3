"""Cross-category bench aggregator — REPORTING ONLY, no solving.

This is a thin wrapper around the existing per-phase runners' own `report`
subcommand (and a few already-written report.json files). It NEVER runs a solve
session, never reads a scorer key / vault, and never unlocks anything. It only
collects results the sanctioned runners already produced and renders a single
unified conversion table.

Design note (matches the project's honest-measurement stance): NYU CTF Bench is a
public / contaminated set, so this reports PAIRED C0-vs-C1 CONVERSIONS (did the
knowledge pack + tool convert a prior failure?) plus whether the tool was actually
attributed — NOT a headline "we solve X%" skill claim.

Usage:
    python3 eval/bench_report.py            # print the unified table to stdout
    python3 eval/bench_report.py --write    # splice it into RESULTS.md markers

Locked categories (store dir chmod 000 after a prior run) are shown as LOCKED with
the exact unlock command; run that in an environment where the runner may touch the
vault, then re-run this aggregator.
"""
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_MD = PROJECT_ROOT / "RESULTS.md"
MARK_START = "<!-- BENCH_TABLE_START -->"
MARK_END = "<!-- BENCH_TABLE_END -->"

# Sources: each is either a paired-conversion RUNNER (shell its `report`) or a
# COUNT report.json already on disk. Nothing here solves or unlocks.
CONVERSION_RUNNERS = [
    ("rev", "p40_rev_runner", "Reverse — router pack + angr (P40)"),
    ("rev", "p41_rev_runner", "Reverse — fair re-measure, persisted /work (P41)"),
    ("pwn", "p38_pwn_runner", "Pwn — knowledge pack A/B (P38)"),
    ("pwn", "p39_pwn_runner", "Pwn — knowledge pack A/B (P39)"),
]
COUNT_REPORTS = [
    ("ai", "store/p27_ai/report.json", "AI guardrail — experience on/off (P27)"),
    ("misc", "store/p51_misc/cycle1_report.json", "Misc/Forensics — blind dev batch (P51)"),
]


def _run_report(runner):
    """Shell `python3 eval/<runner>.py report`; return (ok, parsed_json_or_errstr)."""
    try:
        proc = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "eval" / f"{runner}.py"), "report"],
            cwd=str(PROJECT_ROOT), capture_output=True, text=True, timeout=120,
        )
    except Exception as e:  # noqa: BLE001
        return False, f"invoke-failed: {e}"
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = "LOCKED" if any("Permission denied" in ln for ln in tail) else "ERROR"
        return False, reason
    out = proc.stdout.strip()
    # The runner may print a human line before the JSON; grab from first brace.
    i = out.find("{")
    if i < 0:
        return False, "no-json"
    try:
        return True, json.loads(out[i:])
    except json.JSONDecodeError:
        return False, "bad-json"


def _summarize_conversion(data):
    """Normalize a conversion_table report into counts. Tolerant of field drift."""
    rows = data.get("conversion_table") or []
    n = len(rows)
    c0_solved = c1_solved = conversions = tool_attr = 0
    for r in rows:
        c0b = str((r.get("c0") or {}).get("bucket", "")).upper()
        c1b = str((r.get("c1") or {}).get("bucket", "")).upper()
        if c0b == "SOLVED":
            c0_solved += 1
        if c1b == "SOLVED":
            c1_solved += 1
        if c0b == "FAILED" and c1b == "SOLVED":
            conversions += 1
        # attribution flag name varies by category (angr_/tool_)
        if any(bool(v) for k, v in r.items() if k.endswith("attributed_conversion")):
            tool_attr += 1
    return {"n": n, "c0_solved": c0_solved, "c1_solved": c1_solved,
            "conversions": conversions, "tool_attributed": tool_attr}


def _summarize_count(data):
    """Normalize a count-style report.json (total_solved/n_dev or c0/c2 solved)."""
    if "total_solved" in data:
        n = data.get("n_dev") or (len(data.get("solved", [])) + len(data.get("failed", [])))
        return {"kind": "count", "n": n, "solved": data.get("total_solved")}
    if "c0" in data and ("c2" in data or "c1" in data):
        arm = data.get("c2") or data.get("c1")
        base = data.get("c0")
        return {"kind": "ab_count", "n": arm.get("n"),
                "base_solved": base.get("solved"), "arm_solved": arm.get("solved"),
                "base_attempts": base.get("attempts_mean"), "arm_attempts": arm.get("attempts_mean")}
    return {"kind": "unknown"}


def build_table():
    lines = []
    lines.append("**Paired conversion (C0 = no pack/tool · C1 = pack + tool).** "
                 "NYU bench is public/contaminated → conversions, not a skill-% claim.\n")
    lines.append("| 카테고리 | 측정 | n | C0 해결 | C1 해결 | 전환(C0실패→C1해결) | 도구귀속 전환 |")
    lines.append("|---|---|---|---|---|---|---|")
    any_locked = []
    for cat, runner, label in CONVERSION_RUNNERS:
        ok, res = _run_report(runner)
        if not ok:
            lines.append(f"| {cat} | {label} | — | — | — | — | _{res}_ |")
            if res == "LOCKED":
                any_locked.append(runner)
            continue
        s = _summarize_conversion(res)
        lines.append(f"| {cat} | {label} | {s['n']} | {s['c0_solved']} | {s['c1_solved']} "
                     f"| {s['conversions']} | {s['tool_attributed']} |")

    lines.append("")
    lines.append("**Count / experience (A/B).**\n")
    lines.append("| 카테고리 | 측정 | n | 해결 | 비고 |")
    lines.append("|---|---|---|---|---|")
    for cat, relpath, label in COUNT_REPORTS:
        p = PROJECT_ROOT / relpath
        if not p.exists():
            lines.append(f"| {cat} | {label} | — | — | _missing_ |")
            continue
        try:
            data = json.loads(p.read_text())
        except Exception as e:  # noqa: BLE001
            lines.append(f"| {cat} | {label} | — | — | _read-fail: {e}_ |")
            continue
        s = _summarize_count(data)
        if s.get("kind") == "count":
            lines.append(f"| {cat} | {label} | {s['n']} | {s['solved']} | blind dev |")
        elif s.get("kind") == "ab_count":
            note = (f"experience on/off: {s['base_solved']}/{s['n']}→{s['arm_solved']}/{s['n']} 해결, "
                    f"평균시도 {s['base_attempts']}→{s['arm_attempts']}")
            lines.append(f"| {cat} | {label} | {s['n']} | {s['arm_solved']} | {note} |")
        else:
            lines.append(f"| {cat} | {label} | — | — | _unrecognized shape_ |")

    if any_locked:
        lines.append("")
        lines.append("> **Locked**: 아래 러너의 store가 잠겨 있습니다. 해당 환경에서 unlock 후 재집계:")
        for runner in any_locked:
            lines.append(f">   `python3 eval/{runner}.py unlock && python3 eval/bench_report.py --write`")
    lines.append("")
    lines.append(f"_생성: `python3 eval/bench_report.py`_")
    return "\n".join(lines)


def write_into_results(table):
    text = RESULTS_MD.read_text()
    if MARK_START not in text or MARK_END not in text:
        print(f"markers not found in {RESULTS_MD}", file=sys.stderr)
        return 1
    pre = text.split(MARK_START)[0]
    post = text.split(MARK_END)[1]
    RESULTS_MD.write_text(f"{pre}{MARK_START}\n{table}\n{MARK_END}{post}")
    print(f"wrote table into {RESULTS_MD}")
    return 0


def main(argv):
    table = build_table()
    if "--write" in argv:
        return write_into_results(table)
    print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
