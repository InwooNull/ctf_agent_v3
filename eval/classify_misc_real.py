"""Phase 18 classifier for the real NYU forensics/misc set.

Buckets every loaded challenge (+ the one externally-hosted challenge that could
not be loaded) as:
  A-local   solvable offline from the provided material with ctfagent-misc:0.1
            (--network none): stego / carving / metadata / pcap / document / disk
            image / static ELF, or the flag is already in the prompt.
  B-server  needs a live remote service (no local solvable material; the bench
            ships compose / internal_port). Excluded from this phase.
  C-unrunnable  needs tooling/platform the image lacks (Android APK, iOS package)
            or a file the bench does not ship (external download link).

Signals used (all public / deployment metadata, never a writeup/solution):
  - provided public files + their `file(1)` type, sniffed INSIDE the container;
  - the bench challenge.json's compose / internal_port (deployment shape);
  - a plaintext-exposure tag: whether the real flag already sits in the public
    description or in a provided file (read from the scorer key — this is a
    grader-side catalog tool, not the blind solver).

  python3 eval/classify_misc_real.py        # -> store/p18_misc/classification.{json,md}
"""
import json
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
V = PROJECT / "vault"
ARENA = PROJECT / "arena" / "real_misc"
MANIFEST = V / "manifest_misc_real.json"
KEYS = V / "scorer_keys_misc_real"
SRC = V / "src_real" / "nyu"
OUT = PROJECT / "store" / "p18_misc"
IMAGE = "ctfagent-misc:0.1"

# Challenges whose listed file is hosted externally (download link), not shipped
# in the bench, so they could not be loaded at all.
EXTERNAL_MISSING = {
    "2023f-for-forensings": {"category": "forensics", "split": "holdout",
                             "reason": "listed file forensings.zip is an external download link, not in the bench"},
}

ANDROID = ("android package", "dalvik", "dex")
IOS = ("iphoneos", "debian binary package")


def file_types():
    """filename -> file(1) type, sniffed inside the container (no host analysis)."""
    sh = ("cd /input && for d in */; do for f in \"$d\"*; do "
          "[ \"$(basename \"$f\")\" = challenge.json ] && continue; "
          "[ -f \"$f\" ] && printf '%s\\t%s\\n' \"$f\" \"$(file -b \"$f\")\"; done; done")
    p = subprocess.run(["docker", "run", "--rm", "--network", "none",
                        "-v", f"{ARENA}:/input:ro", IMAGE, "sh", "-c", sh],
                       capture_output=True, text=True)
    out = {}
    for line in p.stdout.splitlines():
        if "\t" in line:
            rel, typ = line.split("\t", 1)
            out.setdefault(rel.split("/", 1)[0], []).append((rel.split("/", 1)[1], typ))
    return out


def bench_meta(rec):
    c = json.loads((SRC / rec["bench_path"] / "challenge.json").read_text())
    return {"compose": bool(c.get("compose")), "internal_port": c.get("internal_port"),
            "box": c.get("box")}


def exposure(cid, rec):
    flag = json.loads((KEYS / f"{cid}.json").read_text())["flag"].encode()
    if flag in (ARENA / cid / "challenge.json").read_bytes():
        return "description"
    for f in (ARENA / cid).iterdir():
        if f.name == "challenge.json":
            continue
        try:
            if flag in f.read_bytes():
                return "file"
        except OSError:
            pass
    return "none"


def classify(cid, rec, types):
    files = types.get(cid, [])
    tset = " ".join(t for _, t in files).lower()
    expo = exposure(cid, rec)
    bm = bench_meta(rec)
    # A flag already present in the prompt or a shipped file is extractable offline
    # (strings/grep), regardless of what the challenge's "intended" platform was.
    if expo == "description":
        return "A", "flag is given in the prompt (trivial; no tool needed)", expo, files, bm
    if expo == "file":
        return "A", "flag is present verbatim in a provided file (strings/grep offline)", expo, files, bm
    if any(a in tset for a in ANDROID):
        return "C", "Android APK/DEX needs apktool/jadx (not in image)", expo, files, bm
    if any(i in tset for i in IOS):
        return "C", "iOS/arm package needs platform tooling (not in image)", expo, files, bm
    if files:
        return "A", "local file(s) analysable offline with the image toolchain", expo, files, bm
    # no provided files
    if bm["compose"] or bm["internal_port"]:
        return "B", "no local file; needs the bench remote service (compose/internal_port)", expo, files, bm
    return "B", "no local file and no local solvable material", expo, files, bm


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    types = file_types()
    rows = []
    for cid, rec in sorted(manifest.items(), key=lambda kv: (kv[1]["category"], kv[0])):
        bucket, reason, expo, files, bm = classify(cid, rec, types)
        rows.append({"cid": cid, "nyu_id": rec["nyu_id"], "category": rec["category"],
                     "split": rec["split"], "bucket": bucket, "reason": reason,
                     "plaintext_exposure": expo,
                     "files": [{"name": n, "type": t} for n, t in files],
                     "server": {"compose": bm["compose"], "internal_port": bm["internal_port"]}})
    # fold in the externally-missing challenge (not loaded) for full 55 accounting
    for nyu_id, info in EXTERNAL_MISSING.items():
        rows.append({"cid": None, "nyu_id": nyu_id, "category": info["category"],
                     "split": info["split"], "bucket": "C", "reason": info["reason"],
                     "plaintext_exposure": "unknown", "files": [], "server": {}})

    counts = {b: sum(1 for r in rows if r["bucket"] == b) for b in ("A", "B", "C")}
    by_cat = {}
    for r in rows:
        by_cat.setdefault(r["category"], {"A": 0, "B": 0, "C": 0})[r["bucket"]] += 1
    exposed = [r for r in rows if r["plaintext_exposure"] in ("description", "file")]

    report = {"image": IMAGE, "total": len(rows), "counts": counts, "by_category": by_cat,
              "plaintext_exposed_count": len(exposed),
              "plaintext_exposed": [{"cid": r["cid"], "nyu_id": r["nyu_id"],
                                     "where": r["plaintext_exposure"]} for r in exposed],
              "rows": rows}
    (OUT / "classification.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    (OUT / "classification.md").write_text(_md(report))
    print(_md(report))
    return 0


def _md(r):
    L = ["# Phase 18 — real NYU forensics/misc classification", "",
         f"- image: `{r['image']}`  total: {r['total']}",
         f"- **A-local {r['counts']['A']} / B-server {r['counts']['B']} / C-unrunnable {r['counts']['C']}**",
         "- by category: " + ", ".join(f"{c} (A{v['A']}/B{v['B']}/C{v['C']})" for c, v in sorted(r["by_category"].items())),
         f"- plaintext-flag exposure (trivial-anchor tag): **{r['plaintext_exposed_count']}** "
         + "[" + ", ".join(f"{e['nyu_id']}:{e['where']}" for e in r["plaintext_exposed"]) + "]",
         "", "| cid | nyu_id | cat | split | bucket | exposure | files | reason |",
         "|-----|--------|-----|-------|--------|----------|-------|--------|"]
    for row in sorted(r["rows"], key=lambda x: (x["bucket"], x["category"], x["nyu_id"])):
        fs = ",".join(f["name"] for f in row["files"]) or "—"
        L.append(f"| {row['cid'] or '—'} | {row['nyu_id']} | {row['category']} | {row['split']} | "
                 f"{row['bucket']} | {row['plaintext_exposure']} | {fs[:40]} | {row['reason']} |")
    L += ["", "A = offline-solvable with the image (--network none). B excluded this phase. "
          "C = tooling/platform/file unavailable. Exposure tag flags challenges whose flag is "
          "already in the prompt or a provided file (for separate trivial-anchor accounting)."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
