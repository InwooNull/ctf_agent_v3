"""Phase 20 loader: NYU CTF Bench web challenges -> our blind layout.

Reuses eval/real_loader.py (same routing/sanitising) re-pointed at web (category fixed to "web",
like the Phase 12 pwn wrapper):
  public  arena/real_web/<wr_xxxxxx>/           listed files + sanitized challenge.json (category "web")
  secret  vault/scorer_keys_web_real/<id>.json  {"flag": ...}
          vault/writeups_web_real/<id>/         reference + every non-listed file of the source dir
                                                (app sources, Dockerfiles, docker-compose, solve
                                                scripts, flag.txt, ...) -> used for A/B/C classification
          vault/manifest_web_real.json          wr id -> nyu id, split, year, event, name, path, hashes
          vault/split_web.json                  dev / holdout id lists

  python3 eval/real_web_loader.py <selection.json> <bench_root>

Blind structure identical to Phase 9/12/18: answers / writeups / Dockerfiles / compose live ONLY in
vault; the agent sees arena/real_web/<id>/ (listed files + title/description/flag_format) and nothing
else. "Author:" lines stripped from the description; flag/points/reference never reach the public JSON.
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
ARENA = PROJECT_ROOT / "arena" / "real_web"
MANIFEST = VAULT / "manifest_web_real.json"
SPLIT = VAULT / "split_web.json"

RL.ARENA = ARENA


def _public_challenge_web(cid, c, files):
    return {"id": cid, "category": "web", "title": c.get("name", ""),
            "description": RL.clean_description(c.get("description", "")),
            "files": files, "flag_format": RL.flag_format(c["flag"])}


RL.public_challenge = _public_challenge_web


def load_one(src, cid, split, nyu_id, meta):
    """Route one bench dir into the web vault/arena layout (keys/writeups renamed for web)."""
    rec = RL.load_one(src, cid, split, nyu_id, meta, arena=ARENA, vault=VAULT)
    rec["category"] = "web"
    # RL.load_one wrote scorer key + writeup under the rev names; move them to web names
    for sub, dest in (("scorer_keys_real", "scorer_keys_web_real"),
                      ("writeups_real", "writeups_web_real")):
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
        raise SystemExit("arena/real_web or vault/manifest_web_real.json already exists; refusing to overwrite")
    manifest, split = {}, {"dev": [], "holdout": []}
    for sp in ("holdout", "dev"):
        for nyu_id in sel[sp]:
            cid = "wr_" + secrets.token_hex(3)
            manifest[cid] = load_one(root / index[nyu_id]["path"], cid, sp, nyu_id, index[nyu_id])
            split[sp].append(cid)
            print(cid, sp, nyu_id)
    MANIFEST.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    SPLIT.write_text(json.dumps(
        {**{k: sorted(v) for k, v in split.items()},
         "rule": "dev = NYU development split (writeups may inform a future C1 pack); holdout = NYU test "
                 "split, never exposed to agents or any experience store"}, indent=1) + "\n")
    print("holdout", len(split["holdout"]), "dev", len(split["dev"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
