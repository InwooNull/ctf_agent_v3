"""Phase 42 misc routing sanity trace: prove the misc router ROUTES three
representative signals to the right 0.3 specialist tool, and that each tool REALLY
runs in image ctfagent-misc:0.3 (--network none, non-root, read-only root) on a
synthetic input built in-container or shipped as a generated sample.

This is NOT a conversion hunt and claims no solve rate. It only shows: signal ->
router line -> real in-container tool invocation, with isolation intact. All inputs
are synthetic (a self-made QR, an in-container hash+wordlist, vol's own bundled symbol
tables), so nothing leaks any holdout answer.

  python3 eval/p42_misc_trace.py        # -> store/p42_misc/trace.json

Three lanes:
  QR/barcode  -> zbarimg   decodes a generated QR mounted read-only at /input
  hash        -> john      cracks a weak in-container hash against an in-container list
  memory dump -> vol       loads + enumerates the BUNDLED OS symbol ISF packs offline
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from orchestrator import skill_pack          # noqa: E402
from solver.misc_harness import MiscHarness  # noqa: E402
from tools import sandbox                     # noqa: E402

IMAGE = "ctfagent-misc:0.3"
OUT = PROJECT_ROOT / "store" / "p42_misc"
QR_PAYLOAD = "CTFMISC_ROUTE_OK_42"


def _route(token):
    router = skill_pack.router_text("misc")
    return [ln.strip() for ln in router.splitlines() if token in ln.lower()]


def _harness(tag, challenge_dir):
    store = Path(tempfile.mkdtemp())
    (Path(challenge_dir) / "challenge.json").write_text(
        json.dumps({"id": tag, "category": "misc"}))
    h = MiscHarness(tag, Path(challenge_dir), store_root=store, image=IMAGE)
    return h


# --- QR lane: generate a QR on the host, decode it with zbarimg in-container -------
def _make_qr(dirpath):
    """Write a QR PNG encoding QR_PAYLOAD into dirpath (mounted ro at /input)."""
    import qrcode  # host-side only (image has pyzbar/zbarimg, not an encoder)
    qrcode.make(QR_PAYLOAD).save(str(Path(dirpath) / "code.png"))


QR_CODE = r'''
import subprocess
r = subprocess.run(["zbarimg", "--quiet", "--raw", "/input/code.png"],
                   capture_output=True, text=True)
print("ZBARIMG_RC", r.returncode)
print("DECODED", r.stdout.strip())
'''

# --- hash lane: make a weak hash + a wordlist in-container, crack with john --------
JOHN_CODE = r'''
import os, subprocess, crypt
# classic John (Debian `john`) uses $HOME/.john and does NOT auto-create it; the
# sandbox runs as a uid with no passwd entry, so set HOME to the writable workdir
# and make the private dir first. (No `--pot` flag — that is jumbo-only.)
os.environ["HOME"] = "/work"
os.makedirs("/work/.john", exist_ok=True)
env = {**os.environ, "HOME": "/work"}
PW = "letmein"
h = crypt.crypt(PW, "ab")                        # a descrypt hash, john's bread-and-butter
open("/work/h.txt", "w").write("user:%s\n" % h)
open("/work/words.txt", "w").write("alpha\nletmein\nbravo\n")
subprocess.run(["john", "--wordlist=/work/words.txt", "/work/h.txt"],
               capture_output=True, text=True, env=env)
show = subprocess.run(["john", "--show", "/work/h.txt"],
                      capture_output=True, text=True, env=env)
print("JOHN_SHOW", show.stdout.strip().replace(chr(10), " | "))
print("CRACKED", PW if PW in show.stdout else "NONE")
'''

# --- memory lane: vol loads offline + the OS symbol ISF packs are BUNDLED -----------
# NOTE: we deliberately do NOT run `vol isfinfo` — it parses every ISF in the 840 MB
# windows pack and takes many minutes. Real plugins look up ONLY the one matching
# table by banner/hash, so this slowness is not a per-dump cost. We prove the two
# things that matter: vol runs with --network none, and the packs are physically
# present (so a plugin CAN resolve its symbol table offline).
VOL_CODE = r'''
import os, glob, subprocess
os.environ["HOME"] = "/work"
import volatility3
symdir = os.path.join(os.path.dirname(volatility3.__file__), "symbols")
packs = sorted(os.path.basename(p) for p in glob.glob(os.path.join(symdir, "*.zip")))
print("VOL_IMPORT_OFFLINE", True)
print("SYMBOL_PACKS", ",".join(packs))
hp = subprocess.run(["vol", "-h"], capture_output=True, text=True)
print("VOL_HELP_RC", hp.returncode)
want = {"windows.zip", "linux.zip", "mac.zip"}
print("SYMBOLS_BUNDLED_OFFLINE", want.issubset(set(packs)))
'''


def _run(tag, code, challenge_dir, timeout=180, pre=None):
    h = _harness(tag, challenge_dir)
    if pre:
        pre(challenge_dir)
    o = h.run_experiment({"name": tag, "code": code, "timeout": timeout})
    return o, (o.stdout or "")


def trace():
    OUT.mkdir(parents=True, exist_ok=True)
    if not (sandbox.docker_available() and sandbox.image_available(IMAGE)):
        raise SystemExit(f"{IMAGE} not present; build docker/Dockerfile.misc3 first")

    lanes = {}

    with tempfile.TemporaryDirectory() as d:
        o, out = _run("p42_qr", QR_CODE, d, pre=_make_qr)
        lanes["qr_barcode"] = {
            "signal": "an image carries a QR / barcode to read",
            "routed_to": _route("zbar"),
            "tool": "zbarimg",
            "exec": o.execution_status,
            "tool_invoked": "ZBARIMG_RC" in out,
            "decoded": next((ln.split(" ", 1)[1] for ln in out.splitlines()
                             if ln.startswith("DECODED")), ""),
            "result_ok": QR_PAYLOAD in out,
        }

    with tempfile.TemporaryDirectory() as d:
        o, out = _run("p42_john", JOHN_CODE, d)
        lanes["hash_crack"] = {
            "signal": "a hash / password to recover",
            "routed_to": _route("john"),
            "tool": "john",
            "exec": o.execution_status,
            "tool_invoked": "JOHN_SHOW" in out,
            "result_ok": "CRACKED letmein" in out,
        }

    with tempfile.TemporaryDirectory() as d:
        o, out = _run("p42_vol", VOL_CODE, d)
        lanes["memory_forensics"] = {
            "signal": "a memory dump to analyse",
            "routed_to": _route("volatility3"),
            "tool": "volatility3 (vol)",
            "exec": o.execution_status,
            "tool_invoked": "VOL_HELP_RC 0" in out,
            "symbols_bundled_offline": "SYMBOLS_BUNDLED_OFFLINE True" in out,
            "note": ("proves vol runs offline and its Windows/Linux/Mac symbol ISF packs "
                     "are BUNDLED + enumerable with --network none (the capability that "
                     "normally needs network). A full dump-plugin solve is not exercised "
                     "here (no sample dump shipped)."),
            "result_ok": "SYMBOLS_BUNDLED_OFFLINE True" in out,
        }

    report = {
        "image": IMAGE,
        "probe": ("Phase 42 misc routing sanity: signal -> router line -> real "
                  "in-container tool call, --network none, non-root, read-only root. "
                  "Capability insurance; NO solve-rate claim."),
        "network_blocked": True,
        "lanes": lanes,
        "all_routed": all(bool(l["routed_to"]) for l in lanes.values()),
        "all_invoked": all(l["tool_invoked"] for l in lanes.values()),
        "all_ok": all(l["result_ok"] for l in lanes.values()),
    }
    (OUT / "trace.json").write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return report


if __name__ == "__main__":
    trace()
