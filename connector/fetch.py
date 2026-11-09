"""Fetch live CTFd challenges into the blind arena layout.

  python3 -m connector.fetch [--only <category>] [--dry-run]

Writes, per challenge, arena/live/<cid>/ :
    challenge.json   {id, category, title, description, files, flag_format,
                      ctfd_id, ctfd_category, value, solved}
    <files...>       every attached file, downloaded verbatim

and store/live/manifest.json mapping cid -> {ctfd_id, category, title, solved}.
The ctfd_id is what connector.submit posts flags against. Already-solved challenges
are recorded but their files are still fetched (harmless, keeps the set complete).

Downloaded files are untrusted data: each lands in its own arena/live/<cid>/ dir and
is never executed from here — only the sandboxed harnesses touch them, by path.
"""
import argparse
import json
import re
import sys
from pathlib import Path

from connector.ctfd_client import (
    CTFdClient, CTFdError, normalize_category, flag_format_from_sample,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARENA = PROJECT_ROOT / "arena" / "live"
STORE = PROJECT_ROOT / "store" / "live"
PUBLIC_KEYS = ("id", "category", "title", "description", "files", "flag_format",
               "ctfd_id", "ctfd_category", "value", "solved")

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_name(name, fallback):
    """Sanitize an attachment filename (strip path components, odd chars)."""
    base = Path(name).name or fallback
    base = _SAFE.sub("_", base).lstrip(".") or fallback
    return base[:128]


def _cid(ctfd_id):
    return f"live_{int(ctfd_id)}"


def _file_urls(detail):
    """CTFd detail 'files' are '/files/<hash>/<name>?token=...' strings."""
    return [f for f in (detail.get("files") or []) if isinstance(f, str)]


def fetch_all(client, only=None, dry_run=False, arena=ARENA, store=STORE):
    summary = client.list_challenges()
    manifest = {}
    results = []
    for ch in summary:
        ctfd_id = ch.get("id")
        cat = normalize_category(ch.get("category"))
        if only and cat != only:
            continue
        cid = _cid(ctfd_id)
        rec = {
            "cid": cid, "ctfd_id": ctfd_id, "category": cat,
            "title": ch.get("name", ""), "solved": bool(ch.get("solved_by_me")),
            "fetched_files": [],
        }
        if dry_run:
            results.append(rec)
            manifest[cid] = {k: rec[k] for k in ("ctfd_id", "category", "title", "solved")}
            continue

        detail = client.get_challenge(ctfd_id)
        dest = Path(arena) / cid
        dest.mkdir(parents=True, exist_ok=True)
        fnames = []
        for i, url in enumerate(_file_urls(detail)):
            raw = client.download_file(url if url.startswith("http") else url)
            # name = last path segment before any query string
            seg = url.split("?", 1)[0].rstrip("/").split("/")[-1]
            fname = _safe_name(seg, f"file{i}")
            (dest / fname).write_bytes(raw)
            fnames.append(fname)
        rec["fetched_files"] = fnames

        desc = detail.get("description", "") or ""
        chal_json = {
            "id": cid,
            "category": cat,
            "title": detail.get("name", rec["title"]),
            "description": desc,
            "files": fnames,
            "flag_format": flag_format_from_sample(_guess_format(desc)),
            "ctfd_id": ctfd_id,
            "ctfd_category": ch.get("category", ""),
            "value": detail.get("value", ch.get("value")),
            "solved": rec["solved"],
        }
        (dest / "challenge.json").write_text(
            json.dumps({k: chal_json[k] for k in PUBLIC_KEYS}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        manifest[cid] = {k: rec[k] for k in ("ctfd_id", "category", "title", "solved")}
        results.append(rec)

    if not dry_run:
        Path(store).mkdir(parents=True, exist_ok=True)
        (Path(store) / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    return results, manifest


def _guess_format(description):
    """Pull a 'xxx{...}' token out of the description if present, else ''."""
    m = re.search(r"[A-Za-z0-9_]+\{[^}]*\}", description or "")
    return m.group(0) if m else ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fetch live CTFd challenges into arena/live/")
    ap.add_argument("--only", choices=["crypto", "pwn", "web", "rev", "misc"],
                    help="fetch only this normalized category")
    ap.add_argument("--dry-run", action="store_true",
                    help="list what would be fetched, download nothing")
    ap.add_argument("--env", default=None, help="path to acdc.env (default config/acdc.env)")
    args = ap.parse_args(argv)
    try:
        client = (CTFdClient.from_env(args.env) if args.env
                  else CTFdClient.from_env())
        results, manifest = fetch_all(client, only=args.only, dry_run=args.dry_run)
    except CTFdError as e:
        print(f"[fetch] ERROR: {e}", file=sys.stderr)
        return 2
    by_cat = {}
    for r in results:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    tag = "DRY-RUN " if args.dry_run else ""
    print(f"[fetch] {tag}{len(results)} challenges  {dict(sorted(by_cat.items()))}")
    for r in results:
        mark = "✓" if r["solved"] else " "
        print(f"  [{mark}] {r['cid']:14} {r['category']:6} {r['title']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
