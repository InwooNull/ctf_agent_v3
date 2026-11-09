"""Host-side deployment resolver for real pwn challenges.

Phase 14 recon found that ~7 A-local give_ups were HARNESS deployment bugs, not capability failures:
the boundary copied `challenge["files"][0]` verbatim to /srv/target and ran it with cwd /srv and the
container's own glibc. That breaks whenever the first public file is an archive (share.zip), a .c
source, or a library, whenever the real binary needs its SHIPPED runtime (custom ld / libc / extra
.so), or whenever the binary reads the flag from a path other than ./flag.txt.

This module resolves a public challenge directory into a clean *deploy directory* (host-side, no code
execution — safe on untrusted archives via zip-slip guards and tarfile `filter='data'`). The deploy
directory is what the pwn-service boundary mounts read-only at /input; tools.pwn_service.boundary_init
reads the manifest it emits and reconstructs the service tree on tmpfs /srv at run time.

Layout produced under `out_dir`:
    out_dir/deploy.json   -- the manifest (below)
    out_dir/tree/...      -- the full extracted/mirrored challenge tree (public; the service runs here)
    out_dir/libs/...      -- shipped shared libraries collected for the runtime (may be absent)
    out_dir/target        -- a stable copy of the selected ELF (public analysis path /input/target)

Manifest keys:
    target_rel     path of the selected ELF within tree/        (e.g. "share/bin/run/chal")
    run_cwd_rel    dir the service chdir()s into, within tree/   (binary's own directory)
    lib_mode       "none" | "ldpath" | "shipped_ld"
    interp         basename of the shipped loader (shipped_ld only), else None
    flag_decoys    tree-relative paths of placeholder flag files to overwrite with the real flag
    binds_port     int if the target binds its own TCP port (serve it directly), else None
    public_files   tree-relative paths worth surfacing to the agent (binary, sources, readme, ...)
    notes          short human strings describing what was resolved
"""
import json
import os
import re
import shutil
import struct
import tarfile
import zipfile
from pathlib import Path

ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar", ".tar.xz", ".tar.bz2")
# glibc family that is coupled to the dynamic loader: in "ldpath" mode (a shipped
# libc with no shipped ld) we must NOT force these onto the container's loader, or
# the version check aborts. The non-glibc extras (libstdc++, libgnustep, ...) are
# safe to preload and are what those challenges actually need.
_LOADER_COUPLED = re.compile(r"^(ld-|ld-linux|libc[.-]|libm[.-]|libpthread[.-]|libdl[.-]|"
                             r"librt[.-]|libresolv[.-]|libnss_|libBrokenLocale)")
_LIB_NAME = re.compile(r"(^ld-|^ld-linux|\.so(\.\d+)*$)")
_LOADER_NAME = re.compile(r"^ld-(linux.*|\d).*\.so")


def _is_archive(name):
    n = name.lower()
    return any(n.endswith(s) for s in ARCHIVE_SUFFIXES)


def _safe_extract_zip(zpath, dest):
    dest = Path(dest).resolve()
    with zipfile.ZipFile(zpath) as z:
        for m in z.namelist():
            # reject absolute paths and traversal
            target = (dest / m).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                raise ValueError(f"zip-slip blocked: {m}")
        z.extractall(dest)


def _safe_extract_tar(tpath, dest):
    with tarfile.open(tpath) as t:
        try:
            t.extractall(dest, filter="data")          # py3.12 sanitising filter
        except TypeError:                               # pragma: no cover (older py)
            t.extractall(dest)


def _elf_info(path):
    """Minimal ELF probe: returns None if not ELF, else (e_type, has_interp)."""
    try:
        with open(path, "rb") as f:
            hdr = f.read(64)
            if hdr[:4] != b"\x7fELF" or len(hdr) < 64:
                return None
            is64 = hdr[4] == 2
            le = "<" if hdr[5] == 1 else ">"
            e_type = struct.unpack(le + "H", hdr[16:18])[0]
            if is64:
                e_phoff = struct.unpack(le + "Q", hdr[32:40])[0]
                e_phentsize = struct.unpack(le + "H", hdr[54:56])[0]
                e_phnum = struct.unpack(le + "H", hdr[56:58])[0]
            else:
                e_phoff = struct.unpack(le + "I", hdr[28:32])[0]
                e_phentsize = struct.unpack(le + "H", hdr[42:44])[0]
                e_phnum = struct.unpack(le + "H", hdr[44:46])[0]
            has_interp = False
            if e_phoff and e_phnum:
                f.seek(e_phoff)
                ph = f.read(e_phentsize * e_phnum)
                for i in range(e_phnum):
                    p = ph[i * e_phentsize:(i + 1) * e_phentsize]
                    if len(p) >= 4 and struct.unpack(le + "I", p[:4])[0] == 3:   # PT_INTERP
                        has_interp = True
                        break
            return (e_type, has_interp)
    except OSError:
        return None


def _looks_like_lib(name):
    return bool(_LIB_NAME.search(name))


def _rel(p, root):
    return str(Path(p).relative_to(root)).replace(os.sep, "/")


def _run_scripts(root):
    """Collect text of run.sh/start.sh for hints on which binary runs and from where."""
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name in ("run.sh", "start.sh") and p.stat().st_size < 4096:
            try:
                out.append((p, p.read_text(errors="replace")))
            except OSError:
                pass
    return out


def resolve(challenge_dir, out_dir, *, challenge=None):
    challenge_dir = Path(challenge_dir)
    out_dir = Path(out_dir)
    tree = out_dir / "tree"
    libs = out_dir / "libs"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    tree.mkdir(parents=True)
    notes = []

    # 1. mirror plain files + extract archives into tree/
    if challenge is None:
        cj = challenge_dir / "challenge.json"
        challenge = json.loads(cj.read_text()) if cj.exists() else {}
    listed = challenge.get("files")
    names = listed if listed else [p.name for p in challenge_dir.iterdir()
                                    if p.name != "challenge.json"]
    for name in names:
        src = challenge_dir / name
        if not src.exists():
            continue
        if _is_archive(name):
            if name.lower().endswith(".zip"):
                _safe_extract_zip(src, tree)
            else:
                _safe_extract_tar(src, tree)
            notes.append(f"extracted archive {name}")
        else:
            shutil.copy2(src, tree / name)

    # 2. classify every file in the mirrored tree
    elfs, libnames = [], []
    for p in sorted(tree.rglob("*")):
        if not p.is_file():
            continue
        info = _elf_info(p)
        if info is None:
            continue
        e_type, has_interp = info
        if _looks_like_lib(p.name):
            libnames.append(p)
        if has_interp and not _looks_like_lib(p.name):
            elfs.append((p, e_type))

    if not elfs:                     # fall back: any ELF that is not clearly a library
        for p in sorted(tree.rglob("*")):
            if p.is_file() and _elf_info(p) and not _looks_like_lib(p.name):
                elfs.append((p, _elf_info(p)[0]))

    if not elfs:
        raise ValueError(f"no runnable ELF found under {challenge_dir}")

    # 3. pick the target: prefer one named by a run script, else the shallowest path
    runtexts = _run_scripts(tree)
    named = set()
    for _, txt in runtexts:
        for m in re.finditer(r"\./([A-Za-z0-9_.-]+)", txt):
            named.add(m.group(1))
    def score(item):
        p = item[0]
        return (0 if p.name in named else 1, len(p.relative_to(tree).parts), str(p))
    target = sorted(elfs, key=score)[0][0]
    notes.append(f"target={_rel(target, tree)}")

    # 4. collect libs + decide runtime mode
    out_dir_libs_used = False
    shipped_ld = None
    for p in libnames:
        if _LOADER_NAME.search(p.name):
            shipped_ld = p
    lib_mode, interp = "none", None
    if libnames:
        libs.mkdir(exist_ok=True)
        if shipped_ld is not None:
            # faithful shipped runtime: ship every library, run via the shipped loader
            for p in libnames:
                shutil.copy2(p, libs / p.name)
            lib_mode, interp = "shipped_ld", shipped_ld.name
            out_dir_libs_used = True
            notes.append(f"shipped_ld={interp} (+{len(libnames)} libs)")
        else:
            # A shipped libc WITHOUT its matching ld cannot be used: the container's ld and a
            # different-version libc mismatch and corrupt TLS/stack-canary setup at startup (observed
            # on brainflop: glibc 2.38 libc + container ld 2.36 -> "stack smashing detected" before
            # main). So ship only the non-glibc extras (libstdc++, libgnustep, ...) and let the
            # container glibc load; a challenge needing a different glibc must ship its ld too
            # (handled by the shipped_ld branch above). If a shipped lib then needs a newer glibc than
            # the container has, the target is undeployable here and is excluded at the runner level.
            extras = [p for p in libnames if not _LOADER_COUPLED.search(p.name)]
            for p in extras:
                shutil.copy2(p, libs / p.name)
            if extras:
                lib_mode = "ldpath"
                out_dir_libs_used = True
                notes.append(f"ldpath +{len(extras)} extra libs (container glibc)")
            else:
                notes.append("shipped libc only, no shipped ld -> use container glibc")
    if not out_dir_libs_used and libs.exists():
        shutil.rmtree(libs)

    # 5. flag decoys + flag paths
    flag_decoys = [_rel(p, tree) for p in tree.rglob("*")
                   if p.is_file() and p.name in ("flag", "flag.txt", "flag.png") and not _elf_info(p)]

    # 6. binds-own-port heuristic (conservative): imports bind()+listen() in the binary
    binds_port = None
    try:
        blob = target.read_bytes()
        if b"bind" in blob and b"listen" in blob and b"socket" in blob:
            m = re.search(rb"(?:PORT|port)[^0-9]{0,8}(\d{2,5})", blob)
            binds_port = int(m.group(1)) if m else 0      # 0 = binds, port unknown (probe)
            notes.append(f"binary may bind its own port ({binds_port or 'unknown'})")
    except OSError:
        pass

    # 7. stable public copy + public file list
    shutil.copy2(target, out_dir / "target")
    public = [_rel(p, tree) for p in sorted(tree.rglob("*"))
              if p.is_file() and p.stat().st_size < 2_000_000
              and not _looks_like_lib(p.name) and p.name not in ("flag", "flag.txt")]

    manifest = {
        "target_rel": _rel(target, tree),
        "run_cwd_rel": _rel(target.parent, tree) if target.parent != tree else ".",
        "lib_mode": lib_mode,
        "interp": interp,
        "flag_decoys": sorted(flag_decoys),
        "binds_port": binds_port,
        "public_files": public,
        "notes": notes,
    }
    (out_dir / "deploy.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    # The deploy dir is mounted read-only at /input; the container root has no CAP_DAC_OVERRIDE, so it
    # can only reach the files if they are world-traversable/readable. They are public, so make it so.
    os.chmod(out_dir, 0o755)
    for p in out_dir.rglob("*"):
        try:
            os.chmod(p, 0o755 if p.is_dir() else (os.stat(p).st_mode | 0o044))
        except OSError:
            pass
    return manifest


if __name__ == "__main__":        # tiny CLI for inspection
    import sys
    print(json.dumps(resolve(sys.argv[1], sys.argv[2]), indent=2))
