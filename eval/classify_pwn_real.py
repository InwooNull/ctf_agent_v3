"""Classify the loaded real pwn problems into A-local / B-server / C-unrunnable and write
store/p12_pwn/classification.{json,md}. Reads the public arena files and the withheld
vault sources/Dockerfiles (classification is a vault-side build step, not the agent path).

  A-local      a runnable x86-64 user-space binary; intended solve is a LOCAL memory-corruption
               exploit (ctfagent-pwn + --network none handles the run/score/session plumbing today).
               NOTE: real CSAW flags live in a server-side flag.txt (== scorer key), not in the public
               files, so blind AGENT measurement still needs a flag-file isolation boundary.
  B-server     needs a genuine multi-service / networked internal environment (not just socat+binary).
  C-*          unrunnable here: arch32 (no i386 runtime in the image), kernel, browser/v8, windows,
               nobinary (source/script only).

  python3 eval/classify_pwn_real.py
"""
import json
import subprocess
import tarfile
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARENA = PROJECT_ROOT / "arena" / "real_pwn"
VAULT = PROJECT_ROOT / "vault"
MANIFEST = VAULT / "manifest_pwn_real.json"
OUT = PROJECT_ROOT / "store" / "p12_pwn"


def _ft(p):
    return subprocess.run(["file", "-b", str(p)], capture_output=True, text=True).stdout.strip()


def _arch(ft):
    if "ELF" not in ft:
        return None
    if "x86-64" in ft:
        return "x86-64"
    if "80386" in ft:
        return "i386"
    if "aarch64" in ft or "ARM" in ft:
        return "arm"
    return "other"


def _elfs(pub, scratch):
    """All ELF arches found in the public files (archives extracted)."""
    arch = {}
    for p in pub.iterdir():
        if p.name == "challenge.json":
            continue
        if p.suffix == ".zip":
            try:
                zipfile.ZipFile(p).extractall(scratch)
            except Exception:
                pass
        elif p.name.endswith((".tar.gz", ".tgz", ".tar")):
            try:
                tarfile.open(p).extractall(scratch)
            except Exception:
                pass
        else:
            (scratch / p.name).write_bytes(p.read_bytes())
    for q in scratch.rglob("*"):
        if q.is_file():
            a = _arch(_ft(q))
            if a:
                arch[q.name] = a
    return arch


def classify_one(cid, meta, scratch):
    pub = ARENA / cid
    wfiles = VAULT / "writeups_pwn_real" / cid / "files"
    wnames = [p.name for p in wfiles.rglob("*") if p.is_file()] if wfiles.exists() else []
    pubnames = [p.name for p in pub.iterdir() if p.name != "challenge.json"]
    elfs = _elfs(pub, scratch)
    archset = set(elfs.values())
    name = meta["name"].lower()
    comp = [p for p in wfiles.rglob("*") if p.name in ("docker-compose.yml", "docker-compose.yaml")] \
        if wfiles.exists() else []
    dock = [p for p in wfiles.rglob("Dockerfile")] if wfiles.exists() else []
    comptxt = " ".join(p.read_text(errors="replace") for p in comp + dock)
    socat = any(w in comptxt for w in ("socat", "ynetd", "xinetd", "nc "))
    nserv = comptxt.count("build:") + comptxt.count("image:") if comp else 0

    kernel = ("kernel" in name) or any(n in ("bzImage", "rootfs.cpio", "rootfs.img", "vmlinux")
                                       or n.endswith(".ko") for n in wnames)
    browser = any(k in name for k in ("es1337", "v8", "chrome")) or any("v8" in n for n in wnames)
    windows = any(n.endswith((".exe", ".dll")) for n in pubnames)
    nobinary = not elfs

    if kernel:
        b, why = "C-kernel", "linux kernel / rootfs challenge"
    elif browser:
        b, why = "C-browser", "js engine / v8 exploitation"
    elif windows:
        b, why = "C-windows", "windows PE binaries"
    elif nobinary:
        b, why = "C-nobinary", f"no ELF in public files ({pubnames})"
    elif "x86-64" in archset:
        # multi-service only if the compose builds >1 real service AND isn't a plain socat wrapper
        if nserv > 1 and not socat:
            b, why = "B-server", f"multi-service compose ({nserv} services)"
        else:
            b, why = "A-local", "x86-64 binary; local exploit (socat/single-service or offline)"
    elif archset <= {"i386"}:
        b, why = "C-arch32", "32-bit x86 only; image has no i386 runtime"
    else:
        b, why = "C-arch", f"non-x86-64 arch {sorted(archset)}"
    return {"cid": cid, "split": meta["split"], "name": meta["name"], "year": meta["year"],
            "event": meta["event"], "bucket": b, "reason": why, "arches": sorted(archset),
            "socat": socat, "n_services": nserv, "public_files": pubnames}


def main():
    manifest = json.loads(MANIFEST.read_text())
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for cid, meta in manifest.items():
            sc = Path(tmp) / cid
            sc.mkdir()
            rows.append(classify_one(cid, meta, sc))
    rows.sort(key=lambda r: (r["bucket"], r["split"], r["year"], r["name"]))
    counts = Counter(r["bucket"] for r in rows)
    coarse = Counter(("A" if r["bucket"] == "A-local" else "B" if r["bucket"] == "B-server" else "C")
                     for r in rows)
    by_split = {sp: Counter(("A" if r["bucket"] == "A-local" else "B" if r["bucket"] == "B-server" else "C")
                            for r in rows if r["split"] == sp) for sp in ("holdout", "dev")}
    report = {
        "total": len(rows), "coarse": dict(coarse), "detailed": dict(sorted(counts.items())),
        "by_split": {k: dict(v) for k, v in by_split.items()},
        "rows": rows,
        "notes": {
            "A_local": "runnable x86-64 binary, local memory-corruption solve; run/score/session plumbing "
                       "works today under --network none. Flag is server-side (flag.txt==key), not in public "
                       "files, so blind AGENT measurement needs a flag-file isolation boundary.",
            "B_server": "genuine multi-service internal network required (deferred).",
            "server_shape": "every 'server' here is socat + one local binary + a server-side flag.txt, not a "
                            "multi-component service; hence B-server (true multi-service) = "
                            + str(coarse.get("B", 0)) + ".",
        },
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "classification.json").write_text(json.dumps(report, indent=2) + "\n")
    (OUT / "classification.md").write_text(_md(report))
    print(_md(report))
    return 0


def _md(r):
    L = ["# Phase 12 — real pwn A/B/C classification", "",
         f"total {r['total']}  |  coarse {r['coarse']}  |  by split {r['by_split']}", "",
         f"detailed: {r['detailed']}", "",
         "| bucket | cid | split | year | name | reason |", "|---|---|---|---|---|---|"]
    for x in r["rows"]:
        L.append(f"| {x['bucket']} | {x['cid']} | {x['split']} | {x['year']} | {x['name']} | {x['reason']} |")
    L += ["", "## notes"]
    for k, v in r["notes"].items():
        L.append(f"- **{k}**: {v}")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
