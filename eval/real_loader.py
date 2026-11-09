"""Phase 9 loader: NYU CTF Bench (CSAW) challenge dirs -> our blind layout.

  python3 eval/real_loader.py <selection.json> <bench_root>
      selection.json: {"holdout": [nyu_id...], "dev": [nyu_id...]}  (ids from the bench *_dataset.json)
      bench_root:     sparse checkout of NYU_CTF_Bench (kept under vault/src_real/)

Per challenge:
  public  arena/real_rev/<rr_xxxxxx>/   files listed in challenge.json "files" (+ sanitized challenge.json:
                                         id, category, title, description, files, flag_format)
  secret  vault/scorer_keys_real/<id>.json   {"flag": ...}
          vault/writeups_real/<id>/          reference url + every NON-listed file of the source dir
                                             (sources, solver scripts, Dockerfiles, flag.txt, ...)
          vault/manifest_real.json           id -> nyu id, split, year, event, name, path, file hashes
          vault/split_real.json              dev / holdout id lists
The loader holds no answers itself; it only routes what the bench ships. Author/reference/flag/points
never reach the public challenge.json, and "Author:" lines are stripped from the description.
"""
import hashlib
import json
import re
import secrets
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARENA = PROJECT_ROOT / "arena" / "real_rev"
VAULT = PROJECT_ROOT / "vault"
PUBLIC_KEYS = ("id", "category", "title", "description", "files", "flag_format")
AUTHOR_LINE = re.compile(r"^\s*(\**\s*author\b.*|by\s+\S+.*)$", re.I)


def flag_format(flag):
    m = re.match(r"^([A-Za-z0-9_]+)\{.*\}$", flag)
    return f"{m.group(1)}{{...}}" if m else "see description"


def clean_description(desc):
    lines = [l for l in desc.replace("\r\n", "\n").split("\n") if not AUTHOR_LINE.match(l)]
    return "\n".join(lines).strip()


def public_challenge(cid, c, files):
    return {"id": cid, "category": "rev", "title": c.get("name", ""),
            "description": clean_description(c.get("description", "")),
            "files": files, "flag_format": flag_format(c["flag"])}


def load_one(src, cid, split, nyu_id, meta, arena=ARENA, vault=VAULT):
    """src: bench challenge dir. Returns the manifest record."""
    c = json.loads((src / "challenge.json").read_text())
    pub = Path(arena) / cid
    pub.mkdir(parents=True)
    listed, names = set(), []
    for f in c.get("files", []):
        p = (src / f).resolve()
        if not p.is_file() or src.resolve() not in p.parents:
            raise FileNotFoundError(f"{nyu_id}: listed file {f!r} missing")
        name = p.name
        if name in names:
            raise ValueError(f"{nyu_id}: duplicate public file name {name}")
        shutil.copyfile(p, pub / name)
        (pub / name).chmod(0o755 if p.stat().st_mode & 0o111 else 0o644)
        listed.add(p)
        names.append(name)
    pc = public_challenge(cid, c, names)
    (pub / "challenge.json").write_text(json.dumps(pc, indent=1) + "\n")
    keys = Path(vault) / "scorer_keys_real"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / f"{cid}.json").write_text(json.dumps({"flag": c["flag"]}) + "\n")
    wu = Path(vault) / "writeups_real" / cid
    wu.mkdir(parents=True)
    (wu / "reference.json").write_text(json.dumps({"reference": c.get("reference"), "author": c.get("author"),
                                                   "nyu_id": nyu_id}, indent=1) + "\n")
    hidden = []
    for p in sorted(src.rglob("*")):
        if p.is_file() and p.resolve() not in listed:
            rel = p.relative_to(src)
            (wu / "files" / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, wu / "files" / rel)
            hidden.append(str(rel))
    return {"nyu_id": nyu_id, "split": split, "year": meta["year"], "event": meta["event"],
            "name": meta["challenge"], "bench_path": meta["path"],
            "public_files": {n: hashlib.sha256((pub / n).read_bytes()).hexdigest() for n in names},
            "withheld_files": hidden}


def main(argv):
    sel = json.loads(Path(argv[0]).read_text())
    root = Path(argv[1])
    index = {}
    for fn in ("test_dataset.json", "development_dataset.json"):
        index.update(json.loads((root / fn).read_text()))
    manifest_p = VAULT / "manifest_real.json"
    if manifest_p.exists() or ARENA.exists():
        raise SystemExit("arena/real_rev or vault/manifest_real.json already exists; refusing to overwrite")
    manifest, split = {}, {"dev": [], "holdout": []}
    for sp in ("holdout", "dev"):
        for nyu_id in sel[sp]:
            cid = "rr_" + secrets.token_hex(3)
            manifest[cid] = load_one(root / index[nyu_id]["path"], cid, sp, nyu_id, index[nyu_id])
            split[sp].append(cid)
            print(cid, sp, "loaded")
    manifest_p.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    (VAULT / "split_real.json").write_text(json.dumps(
        {**{k: sorted(v) for k, v in split.items()},
         "rule": "dev = NYU development split (writeups may inform a future C1 pack); holdout = NYU test "
                 "split, never exposed to agents or any experience store"}, indent=1) + "\n")
    print("holdout", len(split["holdout"]), "dev", len(split["dev"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
