"""Phase 12 loader: NYU CTF Bench pwn challenges -> our blind layout.

Reuses eval/real_loader.py (same routing/sanitising) re-pointed at pwn:
  public  arena/real_pwn/<rp_xxxxxx>/            listed files + sanitized challenge.json (category "pwn")
  secret  vault/scorer_keys_pwn_real/<id>.json   {"flag": ...}
          vault/writeups_pwn_real/<id>/          reference + every non-listed file (sources, Dockerfiles,
                                                 docker-compose, solve scripts, flag.txt, ...)
          vault/manifest_pwn_real.json           rp id -> nyu id, split, year, event, name, path, hashes
          vault/split_pwn.json                   dev / holdout id lists

  python3 eval/real_pwn_loader.py <selection.json> <bench_root>

Blind structure identical to Phase 9: answers / writeups / Dockerfiles live only in vault; the agent sees
arena/real_pwn/<id>/ (files + title/description/flag_format) and nothing else.
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
ARENA = PROJECT_ROOT / "arena" / "real_pwn"
MANIFEST = VAULT / "manifest_pwn_real.json"
SPLIT = VAULT / "split_pwn.json"

# re-point the reused loader at the pwn destinations and category
RL.ARENA = ARENA


def _public_challenge_pwn(cid, c, files):
    return {"id": cid, "category": "pwn", "title": c.get("name", ""),
            "description": RL.clean_description(c.get("description", "")),
            "files": files, "flag_format": RL.flag_format(c["flag"])}


RL.public_challenge = _public_challenge_pwn


def load_one(src, cid, split, nyu_id, meta):
    """Route one bench dir into the pwn vault/arena layout (keys/writeups renamed for pwn)."""
    rec = RL.load_one(src, cid, split, nyu_id, meta, arena=ARENA, vault=VAULT)
    # RL.load_one wrote scorer key + writeup under the rev names; move them to pwn names
    for sub, dest in (("scorer_keys_real", "scorer_keys_pwn_real"),
                      ("writeups_real", "writeups_pwn_real")):
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
        raise SystemExit("arena/real_pwn or vault/manifest_pwn_real.json already exists; refusing to overwrite")
    manifest, split = {}, {"dev": [], "holdout": []}
    for sp in ("holdout", "dev"):
        for nyu_id in sel[sp]:
            cid = "rp_" + secrets.token_hex(3)
            manifest[cid] = load_one(root / index[nyu_id]["path"], cid, sp, nyu_id, index[nyu_id])
            split[sp].append(cid)
            print(cid, sp, nyu_id)
    MANIFEST.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    SPLIT.write_text(json.dumps(
        {**{k: sorted(v) for k, v in split.items()},
         "rule": "dev = NYU development split; holdout = NYU test split, never exposed to agents"},
        indent=1) + "\n")
    print("holdout", len(split["holdout"]), "dev", len(split["dev"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
