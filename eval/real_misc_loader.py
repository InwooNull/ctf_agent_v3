"""Phase 18 loader: NYU CTF Bench forensics + misc challenges -> our blind layout.

Reuses eval/real_loader.py (same routing/sanitising) re-pointed at misc/forensics:
  public  arena/real_misc/<mr_xxxxxx>/            listed files + sanitized challenge.json
                                                  (category kept as the bench's own: "misc" or "forensics")
  secret  vault/scorer_keys_misc_real/<id>.json   {"flag": ...}
          vault/writeups_misc_real/<id>/          reference + every non-listed file (sources, solve
                                                  scripts, Dockerfiles, docker-compose, flag.txt, ...)
          vault/manifest_misc_real.json           mr id -> nyu id, split, year, event, name, path,
                                                  category, hashes, withheld files
          vault/split_misc.json                   dev / holdout id lists

  python3 eval/real_misc_loader.py <selection.json> <bench_root>

Blind structure identical to Phase 9/12: answers / writeups / Dockerfiles live only in vault; the agent
sees arena/real_misc/<id>/ (files + title/description/flag_format) and nothing else. Unlike the pwn
wrapper, the category is NOT collapsed — each challenge keeps its real forensics/misc label.
"""
import importlib.util
import json
import secrets
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("real_loader", PROJECT_ROOT / "eval" / "real_loader.py")
RL = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(RL)

VAULT = PROJECT_ROOT / "vault"
ARENA = PROJECT_ROOT / "arena" / "real_misc"
MANIFEST = VAULT / "manifest_misc_real.json"
SPLIT = VAULT / "split_misc.json"

RL.ARENA = ARENA


def _public_challenge_misc(cid, c, files):
    cat = c.get("category", "misc").lower()
    if cat not in ("misc", "forensics"):
        cat = "misc"
    return {"id": cid, "category": cat, "title": c.get("name", ""),
            "description": RL.clean_description(c.get("description", "")),
            "files": files, "flag_format": RL.flag_format(c["flag"])}


RL.public_challenge = _public_challenge_misc


def load_one(src, cid, split, nyu_id, meta):
    rec = RL.load_one(src, cid, split, nyu_id, meta, arena=ARENA, vault=VAULT)
    rec["category"] = json.loads((src / "challenge.json").read_text()).get("category", "misc").lower()
    # RL.load_one wrote the key + writeup under the rev names; move them to misc names
    for sub, dest in (("scorer_keys_real", "scorer_keys_misc_real"),
                      ("writeups_real", "writeups_misc_real")):
        src_path = VAULT / sub / (f"{cid}.json" if "scorer" in sub else cid)
        dst_dir = VAULT / dest
        dst_dir.mkdir(parents=True, exist_ok=True)
        src_path.rename(dst_dir / src_path.name)
    return rec


def main(argv):
    sel = json.loads(Path(argv[0]).read_text())
    root = Path(argv[1])
    index = {}
    for fn in ("test_dataset.json", "development_dataset.json"):
        index.update(json.loads((root / fn).read_text()))
    if MANIFEST.exists() or ARENA.exists():
        raise SystemExit("arena/real_misc or vault/manifest_misc_real.json already exists; refusing to overwrite")
    manifest, split = {}, {"dev": [], "holdout": []}
    for sp in ("holdout", "dev"):
        for nyu_id in sel[sp]:
            cid = "mr_" + secrets.token_hex(3)
            manifest[cid] = load_one(root / index[nyu_id]["path"], cid, sp, nyu_id, index[nyu_id])
            split[sp].append(cid)
            print(cid, sp, manifest[cid]["category"], nyu_id)
    MANIFEST.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    SPLIT.write_text(json.dumps(
        {**{k: sorted(v) for k, v in split.items()},
         "rule": "dev = NYU development split (writeups may inform a future C1 pack); holdout = NYU test "
                 "split, never exposed to agents or any experience store"}, indent=1) + "\n")
    print("holdout", len(split["holdout"]), "dev", len(split["dev"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
