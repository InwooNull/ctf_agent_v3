"""Phase CM6: file/folder contest input — the WHITEHAT-shaped (download-artifact) case.

CM5 closed url/ctfd; dir/file raised NotImplementedError. This wires them, reusing the
EXISTING container sandbox (tools.sandbox) so isolation is unchanged (--network none,
non-root, --cap-drop ALL, no-new-privileges, read-only root, only /work rw, input :ro).
No network/broker is needed — the artifact is local; evidence is the EXECUTION OUTPUT
of the sandboxed analysis (the same discipline the bench verifier uses).

Flow per file challenge (driven by the shared RotationRunner, like the net path):
  magic-byte triage -> analyzer family -> sandboxed scan of /input -> flag in the real
  execution output -> grounded candidate (CM4) -> checkpoint / writeup / candidate board.

Triage maps the artifact to a family + preferred tool (memory->vol3, disk->sleuthkit,
pcap->tshark, archive/office->extract, image->zsteg/stegseek, text/log->parse, binary
->strings). The default analyzer is a sandboxed byte/string scan for the flag; the
specialized tools plug in as the family's command where the image provides them.

Stdlib only; reuses tools.sandbox / triage / classifier, edits none.
"""
import copy
import json
import re
import subprocess
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path

from tools import sandbox
from solver import contest_evidence as ce
from schemas.records import Candidate

# tool-equipped images (CM7). Pinned; resolve_analyzer falls back if one is absent.
MISC_IMAGE = "ctfagent-misc:0.7"   # CM8: baked vol3 symbol cache + dwarf2json Linux ISF path
REV_IMAGE = "ctfagent-rev:0.2"

# magic-byte -> (family, category, preferred tool label)
MEMORY_EXTS = {".raw", ".mem", ".vmem", ".lime", ".dmp", ".core"}
DISK_EXTS = {".img", ".dd", ".e01", ".vmdk"}
# CM9: crypto artifact indicators. ext hints + PEM magic + text-content markers below.
CRYPTO_EXTS = {".pem", ".sage", ".pub", ".priv", ".key", ".enc"}
# small-text crypto content markers (RSA params, PEM blocks, sage scripts, …)
_CRYPTO_MARKERS = (
    b"-----BEGIN", b"BEGIN PUBLIC KEY", b"BEGIN RSA", b"modulus",
    b"ciphertext", b"\"n\":", b"\"e\":", b"\"c\":", b"n =", b"e =", b"c =",
    b"from Crypto", b"import Crypto", b"PublicKey", b"getPrime", b"pow(",
)
# names that, when present in a challenge dir, strongly imply a crypto artifact set
_CRYPTO_NAMES = {"params.json", "cipher.txt", "ciphertext.txt", "pubkey.pem",
                 "public.pem", "key.pem", "flag.enc", "out.txt", "output.txt"}
_CRYPTO_SNIFF_BYTES = 4096


def _crypto_text_signal(path):
    """True if a small text artifact carries crypto markers (RSA params / PEM / sage)."""
    p = Path(path)
    if p.suffix.lower() in CRYPTO_EXTS:
        return True
    try:
        if p.stat().st_size > _CRYPTO_SNIFF_BYTES * 8:
            return False
        head = p.read_bytes()[:_CRYPTO_SNIFF_BYTES]
    except OSError:
        return False
    return any(m in head for m in _CRYPTO_MARKERS)


def sniff(path):
    """Classify one artifact by magic bytes (+ extension hints). Pure, host-side read
    of the first bytes only. Returns (family, category, tool)."""
    p = Path(path)
    ext = p.suffix.lower()
    try:
        with open(p, "rb") as f:
            head = f.read(16)
    except OSError:
        head = b""
    # CM9: a crypto artifact (PEM/sage/key ext, or PEM magic) routes to the crypto
    # harness, NOT the byte scanner — checked before the generic text/binary paths.
    if ext in CRYPTO_EXTS or head[:11] == b"-----BEGIN ":
        return "crypto_artifact", "crypto", "crypto_harness"
    if head[:4] == b"\x7fELF" or head[:2] == b"MZ":
        # CM9: a bare binary is a static-analysis (rev) target -> angr/decompile harness;
        # 'strings' is kept only as the in-harness last-resort fallback, not the route.
        return "binary", "rev", "angr"
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") or head[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcap", "forensics", "tshark"
    if head[:4] == b"PK\x03\x04":
        return "archive", "misc", "extract"
    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:6] in (b"GIF87a", b"GIF89a"):
        return "image", "forensics", "zsteg/stegseek"
    if ext in MEMORY_EXTS:
        return "memory", "forensics", "vol3"
    if ext in DISK_EXTS:
        return "disk", "forensics", "sleuthkit"
    # textish?
    if head and all(b == 9 or b == 10 or b == 13 or 32 <= b < 127 for b in head):
        return "text", "misc", "parse"
    return "unknown", "misc", "strings"


def _dir_crypto_override(files):
    """CM9: a crypto challenge is often a small params/cipher/PEM set whose BIGGEST file
    is unremarkable to magic-byte sniff. Scan the whole set: any crypto-named file or a
    crypto text/ext signal classifies the challenge as crypto (-> crypto harness)."""
    for p in files:
        if p.name.lower() in _CRYPTO_NAMES or _crypto_text_signal(p):
            return True
    return False


def _is_elf(path):
    """True if `path` is an ELF binary (host-side magic read)."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


# a Dockerfile wiring a binary behind a socket = a remote-service (pwn) deployment.
_SERVICE_MARKERS = (b"socat", b"ncat", b"xinetd", b" nc ", b"tcp-listen",
                    b"tcp_listen", b"listen:", b"ctfd", b"redir", b"EXEC:")


def _pwn_shape(files, challenge_dir):
    """True when the file set looks like a REMOTE binary-exploitation deployment:
    an ELF binary plus service scaffolding (a Dockerfile, or a `deploy/` directory).

    This distinguishes a served pwn target (prob + Dockerfile(socat) + flag) from a
    standalone rev/crackme binary. A lone ELF with no deployment scaffolding stays rev."""
    if not any(_is_elf(p) for p in files):
        return False
    root = Path(challenge_dir)
    names = {p.name.lower() for p in files}
    # a `deploy/` directory anywhere in the set is a strong deployment signal
    in_deploy = any("deploy" in p.relative_to(root).parent.parts for p in files)
    if "dockerfile" in names or in_deploy:
        return True
    return False


_FMT_RE = re.compile(rb"([A-Za-z0-9_]{1,16})\{")
_FLAG_FILE_NAMES = ("flag", "flag.txt", "flag.json")


def _detect_flag_format(challenge_dir):
    """Infer the flag format (e.g. 'DH{...}') from a placeholder `flag` file or a
    Dockerfile reference. Returns a format string or None when nothing is found.

    The deployed `flag` file is usually a placeholder like `DH{flag}`; its PREFIX is
    the real challenge's flag format, which the verifier needs to accept the flag."""
    root = Path(challenge_dir)
    cands = [p for p in root.rglob("*") if p.is_file()
             and p.name.lower() in _FLAG_FILE_NAMES]
    cands += [p for p in root.rglob("*") if p.is_file() and p.name == "Dockerfile"]
    for p in cands:
        try:
            if p.stat().st_size > 65536:
                continue
            head = p.read_bytes()[:4096]
        except OSError:
            continue
        m = _FMT_RE.search(head)
        if m:
            return m.group(1).decode("latin1") + "{...}"
    return None


def triage_dir(challenge_dir):
    """Pick a representative family/category/tool for a challenge's file set (the
    largest file decides; ties by name). A crypto-artifact signal anywhere in the set
    overrides the largest-file pick (CM9); a remote-service ELF deployment (Dockerfile
    + binary, or a deploy/ dir) routes to the pwn harness instead of rev."""
    files = [p for p in sorted(Path(challenge_dir).rglob("*")) if p.is_file()]
    if not files:
        return "unknown", "misc", "strings", []
    rel = [str(p.relative_to(challenge_dir)) for p in files]
    biggest = max(files, key=lambda p: (p.stat().st_size, p.name))
    fam, cat, tool = sniff(biggest)
    # A binary present anywhere is a rev target; but a crypto set wins (a .pem/params
    # beside a helper binary is still a crypto challenge).
    if cat != "crypto" and _dir_crypto_override(files):
        fam, cat, tool = "crypto_artifact", "crypto", "crypto_harness"
    # A served binary (Dockerfile/socat or deploy/ beside an ELF) is a remote pwn, not a
    # standalone rev target -> route to the (benign) local pwn harness.
    elif cat != "crypto" and _pwn_shape(files, challenge_dir):
        fam, cat, tool = "binary", "pwn", "pwn_local"
    return fam, cat, tool, rel


def _safe_extract_archive(path):
    """Host-side extract a zip/tar archive to a fresh temp dir, with a path-traversal
    (zip-slip) guard. Returns the extraction dir, or None when `path` is not a
    stdlib-extractable archive (7z/rar fall back to the in-sandbox extract analyzer)."""
    dest = Path(tempfile.mkdtemp(prefix="solve_extract_"))

    def _within(base, target):
        try:
            Path(target).resolve().relative_to(Path(base).resolve())
            return True
        except ValueError:
            return False

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for n in zf.namelist():
                    if not _within(dest, dest / n):
                        continue
                    zf.extract(n, dest)
            return dest
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                safe = [m for m in tf.getmembers() if _within(dest, dest / m.name)]
                tf.extractall(dest, members=safe)   # members pre-filtered for traversal
            return dest
    except (OSError, zipfile.BadZipFile, tarfile.TarError):
        return None
    return None


def file_items_from_input(path):
    """Build contest challenge items from a file or folder.

    archive file    -> extract, then re-triage the CONTENTS as one challenge (so a
                       pwn/rev binary inside a zip reaches its real harness).
    file            -> one challenge (that file).
    dir with subdirs-> each immediate subdir is a challenge (its files).
    dir of files    -> one challenge (all files).
    """
    p = Path(path)
    items = []
    if p.is_file():
        fam, cat, tool = sniff(p)
        # CM9: a lone text artifact carrying crypto markers (params/cipher) is crypto.
        if cat != "crypto" and _crypto_text_signal(p):
            fam, cat, tool = "crypto_artifact", "crypto", "crypto_harness"
        # An archive is not itself the challenge: extract and re-triage its contents so
        # a bundled binary/key/dump routes to the right harness instead of a blind byte
        # scan of the archive. (7z/rar that stdlib can't open keep the old extract path.)
        if fam == "archive":
            extracted = _safe_extract_archive(p)
            if extracted is not None:
                fam, cat, tool, files = triage_dir(extracted)
                it = _mk(p.stem or "chal", extracted, files, fam, cat, tool)
                it["flag_format"] = _detect_flag_format(extracted) or it["flag_format"]
                return [it]
        items.append(_mk(p.stem or "chal", p.parent, [p.name], fam, cat, tool))
        return items
    subdirs = [c for c in sorted(p.iterdir()) if c.is_dir()]
    targets = subdirs if subdirs else [p]
    for d in targets:
        fam, cat, tool, files = triage_dir(d)
        cid = d.name if d != p else (p.name or "chal")
        it = _mk(cid, d, files, fam, cat, tool)
        it["flag_format"] = _detect_flag_format(d) or it["flag_format"]
        items.append(it)
    return items


def _mk(cid, file_dir, files, fam, cat, tool):
    return {"id": cid, "solve_kind": "file", "file_dir": str(file_dir), "files": files,
            "family": fam, "category": cat, "tool": tool, "flag_format": "flag{...}",
            "score": 100, "difficulty": "med", "est_cost": 1.0}


_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}")

# ---- analyzer drivers (run as `python3 -c <DRIVER>` inside the mapped image) -------
# Each prints bytes containing any recovered flag to stdout; evidence = that output.
# All writes go to /work (rw); HOME/TMPDIR are repointed there so tools work under the
# governance read-only root.

_SCAN_DRV = r"""
import os,re,sys
rx=re.compile(rb'[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}')
for r,_,fs in os.walk('/input'):
  for fn in fs:
    try: data=open(os.path.join(r,fn),'rb').read()
    except OSError: continue
    for m in rx.finditer(data): sys.stdout.buffer.write(b'FOUND '+m.group(0)+b'\n')
"""

_TSHARK_DRV = r"""
import os,sys,subprocess,binascii,gzip
os.environ.update(HOME='/work',TMPDIR='/work',XDG_CACHE_HOME='/work')
for r,_,fs in os.walk('/input'):
  for fn in fs:
    p=os.path.join(r,fn)
    try: out=subprocess.run(['tshark','-r',p,'-T','fields','-e','data'],capture_output=True,timeout=60).stdout
    except Exception: continue
    for tok in out.split():
      try: raw=binascii.unhexlify(tok.strip())
      except Exception: continue
      try: raw=gzip.decompress(raw)
      except Exception: pass
      sys.stdout.buffer.write(raw+b'\n')
"""

_IMAGE_DRV = r"""
import os,sys,subprocess
os.environ.update(HOME='/work',TMPDIR='/work',XDG_CACHE_HOME='/work')
for r,_,fs in os.walk('/input'):
  for fn in fs:
    p=os.path.join(r,fn)
    for cmd in (['exiftool',p],['zsteg','-a',p],['strings','-n','6',p]):
      try: sys.stdout.buffer.write(subprocess.run(cmd,capture_output=True,timeout=60).stdout+b'\n')
      except Exception: pass
"""

_MEM_DRV = r"""
import os,sys,subprocess,shutil
os.environ.update(HOME='/work',TMPDIR='/work',XDG_CACHE_HOME='/work')
# CM8: seed vol3's symbol-identifier cache from the image-baked FULL index so the first
# symbol lookup is a cache HIT. Without this, vol3's cold scan of the 801MB windows pack
# (minutes) blows the timeout and the path silently degrades to a strings scan.
baked=os.environ.get('VOL_BAKED_CACHE','/opt/ctfagent/volcache')
try:
    if os.path.isdir(baked): shutil.copytree(baked,'/work',dirs_exist_ok=True)
except Exception as e: sys.stderr.write('cache-seed-warn %s\n'%e)
def vol(args,t=90):
    try: return subprocess.run(['vol','-q']+args,capture_output=True,timeout=t).stdout
    except Exception: return b''
WINDOWS=('windows.pslist.PsList','windows.pstree.PsTree','windows.cmdline.CmdLine',
         'windows.netscan.NetScan','windows.hashdump.Hashdump')
LINUX=('linux.pslist.PsList','linux.bash.Bash')
for r,_,fs in os.walk('/input'):
  for fn in fs:
    p=os.path.join(r,fn)
    info=vol(['-f',p,'windows.info.Info'],t=180)
    if b'Kernel Base' in info or b'NTBuildLab' in info:          # real Windows image
        sys.stdout.buffer.write(b'##REALSTRUCT## windows '+fn.encode()+b'\n'+info+b'\n')
        for plug in WINDOWS: sys.stdout.buffer.write(vol(['-f',p,plug])+b'\n')
        continue
    linux_ok=False                                               # Linux: ISF on the fly
    for plug in LINUX:
        try: out=subprocess.run(['vol-linux-isf',p,plug],capture_output=True,timeout=180).stdout
        except Exception: out=b''
        if b'##NEED##' in out:
            sys.stdout.buffer.write(out); break                  # host -> needs.jsonl
        if out.strip():
            if not linux_ok:
                sys.stdout.buffer.write(b'##REALSTRUCT## linux '+fn.encode()+b'\n'); linux_ok=True
            sys.stdout.buffer.write(out+b'\n')
    try: sys.stdout.buffer.write(subprocess.run(['strings','-n','6',p],capture_output=True,timeout=90).stdout+b'\n')
    except Exception: pass
"""

_DISK_DRV = r"""
import os,sys,subprocess
os.environ.update(HOME='/work',TMPDIR='/work')
for r,_,fs in os.walk('/input'):
  for fn in fs:
    p=os.path.join(r,fn)
    for cmd in (['fls','-r','-p',p],['strings','-n','6',p]):
      try: sys.stdout.buffer.write(subprocess.run(cmd,capture_output=True,timeout=90).stdout+b'\n')
      except Exception: pass
"""

_REV_DRV = r"""
import os,sys,subprocess
os.environ.update(HOME='/work',TMPDIR='/work')
for r,_,fs in os.walk('/input'):
  for fn in fs:
    p=os.path.join(r,fn)
    try: sys.stdout.buffer.write(subprocess.run(['strings','-n','5',p],capture_output=True,timeout=60).stdout+b'\n')
    except Exception: pass
"""

_EXTRACT_DRV = r"""
import os,sys,subprocess,re
os.environ.update(HOME='/work',TMPDIR='/work')
rx=re.compile(rb'[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}')
ex='/work/ex'; os.makedirs(ex,exist_ok=True)
for r,_,fs in os.walk('/input'):
  for fn in fs:
    p=os.path.join(r,fn)
    for cmd in (['7z','x','-y','-o'+ex,p],['tar','xf',p,'-C',ex]):
      try:
        if subprocess.run(cmd,capture_output=True,timeout=120).returncode==0: break
      except Exception: pass
for base in (ex,'/input'):
  for r,_,fs in os.walk(base):
    for fn in fs:
      try: data=open(os.path.join(r,fn),'rb').read()
      except OSError: continue
      for m in rx.finditer(data): sys.stdout.buffer.write(b'FOUND '+m.group(0)+b'\n')
"""

DRIVERS = {"scan": _SCAN_DRV, "tshark": _TSHARK_DRV, "forensic_image": _IMAGE_DRV,
           "vol3": _MEM_DRV, "sleuthkit": _DISK_DRV, "rev": _REV_DRV, "extract": _EXTRACT_DRV}

# family -> (tool image or None for the default image, analyzer key)
FAMILY_ANALYZER = {
    "pcap": (MISC_IMAGE, "tshark"),
    "memory": (MISC_IMAGE, "vol3"),
    "disk": (MISC_IMAGE, "sleuthkit"),
    "image": (MISC_IMAGE, "forensic_image"),
    "archive": (MISC_IMAGE, "extract"),
    "binary": (REV_IMAGE, "rev"),
    "text": (None, "scan"),
    "unknown": (None, "scan"),
}

# Per-family driver timeout (s). Memory runs several vol3 plugins over a multi-hundred-MB
# dump; with misc:0.7's baked symbol cache each lookup is a cache hit, so this is headroom,
# not a hot loop. Others keep the run_in_image default.
_FAMILY_TIMEOUT = {"memory": 600, "disk": 300}


def _default_image():
    return sandbox.load_sandbox_config()["container"].get("image")


def resolve_analyzer(family, available=None):
    """Map a family to (image, analyzer_key, driver, is_fallback, reason).

    If the family's tool image is absent, fall back to the default-image byte scanner
    and report a reason (so the caller can log a needs entry)."""
    available = available or sandbox.container_backend_ready
    image, key = FAMILY_ANALYZER.get(family, (None, "scan"))
    if image is None:                                   # families handled by the scanner
        return _default_image(), "scan", DRIVERS["scan"], False, None
    if available(image):
        return image, key, DRIVERS[key], False, None
    return (_default_image(), "scan", DRIVERS["scan"], True,
            f"tool_image_unavailable:{image}:{key}")


def run_in_image(image, inner_argv, challenge_dir, jail_root, name, timeout=180):
    """Run inner_argv in `image` under the governance container profile (a runtime COPY
    of config/sandbox.json with only `image` repointed — sandbox.py/json unedited).
    Isolation unchanged: --network none, non-root, cap-drop ALL, no-new-privileges,
    read-only root, /work rw, /input ro. Returns (stdout_text, status)."""
    base = sandbox.load_sandbox_config()["container"]
    if not sandbox.container_backend_ready(image):
        return "", "no_container"
    cfg = copy.deepcopy(base)
    cfg["image"] = image
    Path(jail_root).mkdir(parents=True, exist_ok=True)
    argv = sandbox.build_container_argv(inner_argv, jail_root, cfg, name,
                                        input_dir=str(challenge_dir), timeout=None)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "", "timeout"
    return proc.stdout, ("ok" if proc.returncode == 0 else f"rc{proc.returncode}")


# back-compat alias (CM6 default scanner path)
def sandbox_scan(challenge_dir, files, jail_root, name, timeout=60):
    return run_in_image(_default_image(), ["python3", "-c", _SCAN_DRV],
                        challenge_dir, jail_root, name, timeout=timeout)


def _log_needs(run_dir, cid, family, image_key, reason):
    p = Path(run_dir) / "needs.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps({"cid": cid, "family": family, "want": image_key,
                            "reason": reason, "type": "tool_gap"}) + "\n")


class FileChallengeCtx:
    """A local file challenge's context (no broker; sandboxed analysis)."""
    kind = "file"

    def __init__(self, cid, category, verifier, flag_format, file_dir, files,
                 prompt, jail_root, family, tool, run_dir=None):
        self.cid = cid
        self.category = category
        self.verifier = verifier
        self.flag_format = flag_format
        self.file_dir = Path(file_dir)
        self.files = files
        self.prompt = prompt
        self.jail_root = Path(jail_root)
        self.family = family
        self.tool = tool
        self.run_dir = Path(run_dir) if run_dir else self.jail_root.parent.parent
        self.skill_injected = False


def file_solver(ctx, round_idx, info, available=None):
    """RotationRunner solver for a file challenge (CM7): route the family to its
    tool-equipped image and run the real analyzer; a flag must appear in the captured
    execution output (no fabricated solve). The default byte scanner is used only as a
    fallback when the tool image is absent, and that fallback is logged as a need."""
    if round_idx > 0:
        return {"info_gain": 0, "log": f"{ctx.tool}: no further analysis step"}
    image, key, driver, fallback, reason = resolve_analyzer(ctx.family, available=available)
    if fallback:
        _log_needs(ctx.run_dir, ctx.cid, ctx.family, reason.split(":", 1)[1], reason)
    name = f"cm7_{ctx.cid}_{uuid.uuid4().hex[:8]}"
    # Memory forensics runs several vol3 plugins over a large dump; give it headroom
    # over the default (symbol lookups are a cache hit on misc:0.7, so this is slack).
    tmo = _FAMILY_TIMEOUT.get(ctx.family, 180)
    out, status = run_in_image(image, ["python3", "-c", driver], ctx.file_dir,
                               ctx.jail_root, name, timeout=tmo)
    # CM8: a tool present but UNABLE to resolve (Linux dump with no challenge-provided
    # kernel symbols) self-reports via a ##NEED## marker -> log a tool_gap need. Real
    # structured output (vol plugins resolved) self-reports via ##REALSTRUCT##.
    realstruct = "##REALSTRUCT##" in out
    for ln in out.splitlines():
        if ln.startswith("##NEED##"):
            try:
                nd = json.loads(ln.split(" ", 1)[1])
            except Exception:
                nd = {"reason": "no_kernel_symbols"}
            _log_needs(ctx.run_dir, ctx.cid, ctx.family, "kernel_symbols",
                       nd.get("reason", "no_kernel_symbols"))
    struct_tag = (" realstruct" if realstruct else (" strings-fallback" if ctx.family == "memory" else ""))
    label = f"{key}@{image}" + ("(fallback)" if fallback else "") + struct_tag
    log = (f"image={image} analyzer={key}{' FALLBACK' if fallback else ''} "
           f"family={ctx.family} status={status} out_bytes={len(out)}{struct_tag}")
    if status != "ok":
        return {"info_gain": 0, "log": log}
    ev = ctx.verifier.capture(ce.SRC_EXEC, out, label=label)
    for m in _FLAG_RE.finditer(out):
        flag = m.group(0)
        if flag.startswith("FOUND"):
            continue
        if ce.matches_format(flag, ctx.flag_format):
            return {"info_gain": 1, "log": log + f" FLAG={flag}",
                    "candidate": Candidate(value=flag, confidence=0.9,
                                           evidence_refs=[ev], status="VERIFIED")}
    return {"info_gain": 1 if out else 0, "log": log + " (no flag in output)"}
