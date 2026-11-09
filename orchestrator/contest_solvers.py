"""Phase CM9: wire the pwn / rev / crypto solving HARNESSES into the contest-mode
dispatch, the same way CM5 wired web and CM6/7 wired file analysis.

This module is THIN WIRING only — it reuses the existing, unchanged harnesses and
session layer; it contains no new solving engine:

  rev    -> solver.rev_harness.RevHarness   (angr/decompile in ctfagent-rev; `strings`
            kept only as the in-harness last-resort fallback, never the route).
  crypto -> solver.crypto_harness.CryptoHarness (sympy/sage path in ctfagent-crypto).
  pwn    -> solver.session.Session driving a tube to the remote target THROUGH the CM2
            EgressBroker (net). Only NON-WEAPONIZING interaction is performed; exploit
            development is the [cyber] gate — if a benign path does not yield the flag
            it is LOGGED and NOT worked around, so the challenge ends honestly via the
            StopLoss no-progress path. Local pwn binaries route to the pwn-service
            isolation harness (solver.pwn_service_harness).

Evidence discipline is identical to CM5/CM6: a flag must appear in a captured EXECUTION
output (SRC_EXEC) or TARGET response (SRC_TARGET); nothing is fabricated, nothing is
auto-submitted. Governance files and the blind bench path are untouched.
"""
import json
import re
import shutil
import uuid
from pathlib import Path

from solver import contest_evidence as ce
from solver import session as S
from schemas.records import Candidate

_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}")
# the solve scripts below print this line on success: "CONTEST_FLAG <route> <flag>"
_CONTEST_FLAG_RE = re.compile(r"^CONTEST_FLAG (\S+) (\S.*)$", re.M)


# ---- in-container solve scripts (run by the harness, python3 -I, /input :ro) --------
# Each prints `CONTEST_FLAG <route> <flag>` on success, else `NO_FLAG`. The flag must be
# produced by the real technique and emitted to stdout — that stdout is the evidence.

REV_ANGR_DRIVER = r"""
import glob, os, re, subprocess, sys
# governance root is read-only; repoint scratch/caches into /work so angr can run.
os.environ.update(HOME='/work', TMPDIR='/work', XDG_CACHE_HOME='/work')
RX = re.compile(rb'[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}')

def is_exe(p):
    try:
        h = open(p, 'rb').read(4)
    except OSError:
        return False
    return h[:4] == b'\x7fELF' or h[:2] == b'MZ'

files = [p for p in glob.glob('/input/**', recursive=True) if os.path.isfile(p)]
targets = [p for p in files if is_exe(p)] or files
flag = route = None

# Primary route: angr symbolic execution — explore for a reachable state whose program
# stdout carries a flag. This is a real solve of the binary's logic, not a string grep.
try:
    import angr, logging
    logging.getLogger('angr').setLevel('CRITICAL')
    for t in targets:
        try:
            proj = angr.Project(t, auto_load_libs=False)
            st = proj.factory.full_init_state(stdin=angr.SimFileStream(name='stdin', has_end=False))
            smg = proj.factory.simulation_manager(st)
            def _found(s):
                # stop only when a COMPLETE flag is on stdout (not mid-print at the '{')
                try:
                    return RX.search(s.posix.dumps(1)) is not None
                except Exception:
                    return False
            smg.explore(find=_found, num_find=1)
            for s in smg.found:
                out = s.posix.dumps(1)
                m = RX.search(out)
                if m:
                    flag, route = m.group(0).decode('latin1'), 'angr'
                    break
        except Exception as e:
            sys.stderr.write('angr-bin-error %s: %s\n' % (t, e))
        if flag:
            break
except Exception as e:
    sys.stderr.write('angr-import-error %s\n' % e)

# Last-resort fallback only: a literal flag string left in the binary.
if not flag:
    for t in targets:
        try:
            out = subprocess.run(['strings', '-n', '5', t], capture_output=True, timeout=30).stdout
        except Exception:
            out = b''
        m = RX.search(out)
        if m:
            flag, route = m.group(0).decode('latin1'), 'strings'
            break

print('CONTEST_FLAG %s %s' % (route, flag) if flag else 'NO_FLAG')
"""

CRYPTO_RSA_DRIVER = r"""
import glob, json, os, re, sys
os.environ.update(HOME='/work', TMPDIR='/work', XDG_CACHE_HOME='/work')
RX = re.compile(r'[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}')

def _load_params():
    # params.json carrying n/e/c is the textbook-RSA shape.
    for p in glob.glob('/input/**', recursive=True):
        if os.path.isfile(p) and p.lower().endswith('.json'):
            try:
                d = json.load(open(p))
                if all(k in d for k in ('n', 'e', 'c')):
                    return d
            except Exception:
                pass
    return None

def _decode(m):
    try:
        b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    except Exception:
        return None
    hit = RX.search(b.decode('latin1'))
    return hit.group(0) if hit else None

flag = route = None
p = _load_params()
if p:
    import sympy
    n, e, c = int(p['n']), int(p['e']), int(p['c'])
    fac = sympy.factorint(n)                       # small-prime factorisation route
    if len(fac) >= 2 or any(k >= 2 for k in fac.values()):
        phi = 1
        for pr, k in fac.items():
            phi *= (pr - 1) * pr ** (k - 1)
        try:
            d = pow(e, -1, phi)
            flag = _decode(pow(c, d, n))
            route = 'rsa_factor'
        except Exception as ex:
            sys.stderr.write('rsa-error %s\n' % ex)

print('CONTEST_FLAG %s %s' % (route, flag) if flag else 'NO_FLAG')
"""


# ---- file-artifact harness solvers (rev / crypto) -----------------------------------

def _harness_input(ctx):
    """Prepare a harness challenge dir (challenge.json + the challenge files) under the
    challenge's jail work dir, WITHOUT mutating the untrusted input dir. Returns its path."""
    hin = Path(ctx.jail_root) / "hin"
    hin.mkdir(parents=True, exist_ok=True)
    src = Path(ctx.file_dir)
    copied = []
    for rel in (ctx.files or []):
        s = src / rel
        if not s.is_file():
            continue
        d = hin / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(s, d)
        copied.append(rel)
    (hin / "challenge.json").write_text(
        json.dumps({"id": ctx.cid, "files": copied, "category": ctx.category}))
    return hin, copied


def _run_file_harness(ctx, harness_cls, driver, timeout, image=None):
    """Drive an existing container harness for one solve experiment; return (stdout,
    status, image). Pure reuse — the harness owns isolation, logging, and the image.

    `image` overrides the harness default when the needed tool lives in a specific
    image tag (e.g. angr is in ctfagent-rev:0.2, not the harness default 0.1)."""
    hin, _ = _harness_input(ctx)
    store = Path(ctx.jail_root) / "hstore"
    run_id = f"{ctx.cid}_{harness_cls.__name__}"
    kw = {"store_root": store}
    if image:
        kw["image"] = image
    h = harness_cls(run_id, hin, **kw)
    outcome = h.run_experiment({"name": "solve", "code": driver, "timeout": timeout,
                                "nondeterministic": False})
    return outcome.stdout or "", outcome.execution_status, h.image


def _solve_via_harness(ctx, harness_cls, driver, default_route, timeout, image=None):
    """Shared rev/crypto contest-solver body: one harness experiment, flag grounded in
    its real execution output."""
    stdout, status, image = _run_file_harness(ctx, harness_cls, driver, timeout, image=image)
    ev = None
    m = _CONTEST_FLAG_RE.search(stdout)
    route = m.group(1) if m else default_route
    fallback = (route == "strings")
    label = f"{route}@{image}" + ("(fallback)" if fallback else "")
    log = (f"image={image} harness={harness_cls.__name__} status={status} "
           f"route={route} out_bytes={len(stdout)}")
    if status != "ok":
        return {"info_gain": 0, "log": log + " (harness did not run)"}
    ev = ctx.verifier.capture(ce.SRC_EXEC, stdout, label=label)
    if m:
        flag = m.group(2).strip()
        if ce.matches_format(flag, ctx.flag_format):
            return {"info_gain": 1, "log": log + f" FLAG={flag}",
                    "candidate": Candidate(value=flag, confidence=0.9,
                                           evidence_refs=[ev], status="VERIFIED")}
    return {"info_gain": 1 if stdout else 0, "log": log + " (no flag in output)"}


def contest_rev_solver(ctx, round_idx, info):
    """Route a rev artifact to the RevHarness angr path (strings only as last resort)."""
    from solver.rev_harness import RevHarness
    from orchestrator.contest_files import REV_IMAGE   # angr lives in rev:0.2
    if round_idx > 0:
        return {"info_gain": 0, "log": "rev: no further analysis step"}
    return _solve_via_harness(ctx, RevHarness, REV_ANGR_DRIVER, "angr",
                              timeout=180, image=REV_IMAGE)


def contest_crypto_solver(ctx, round_idx, info):
    """Route a crypto artifact to the CryptoHarness (sympy/sage) path."""
    from solver.crypto_harness import CryptoHarness
    if round_idx > 0:
        return {"info_gain": 0, "log": "crypto: no further analysis step"}
    return _solve_via_harness(ctx, CryptoHarness, CRYPTO_RSA_DRIVER, "crypto", timeout=120)


# A strictly non-weaponizing local-pwn probe: run the binary in the isolation harness
# and capture only what it VOLUNTEERS (banner + a benign newline nudge). No payload is
# crafted — that is the [cyber]-gated step.
PWN_LOCAL_BENIGN_DRIVER = r"""
import glob, os, re, shutil, sys
RX = re.compile(rb'[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}')
import session

def is_exe(p):
    try:
        return open(p, 'rb').read(4)[:4] == b'\x7fELF'
    except OSError:
        return False

bins = [p for p in glob.glob('/input/**', recursive=True) if os.path.isfile(p)]
t = next((p for p in bins if is_exe(p)), None)
flag = None
if t:
    dst = '/work/target'
    shutil.copy(t, dst)
    os.chmod(dst, 0o755)
    seen = b''
    try:
        with session.Session(argv=[dst], log_dir='/work/sess', wall_s=8) as s:
            try:
                seen += s.recv(4096, timeout=3)
            except Exception:
                pass
            try:
                s.sendline(b'')
                seen += s.recv(4096, timeout=3)
            except Exception:
                pass
    except Exception as e:
        sys.stderr.write('pwn-local-error %s\n' % e)
    m = RX.search(seen)
    if m:
        flag = m.group(0).decode('latin1')
print('CONTEST_FLAG pwn_local %s' % flag if flag else 'NO_FLAG')
"""


def contest_local_pwn_solver(ctx, round_idx, info):
    """Route a LOCAL pwn binary to the pwn isolation harness (ctfagent-pwn, --network
    none, session tube to the local process). Only benign interaction is run; if the
    flag is behind a bug, that weaponization step is the [cyber] gate -> logged, not
    worked around, and the challenge ends via StopLoss."""
    from solver.pwn_harness import PwnHarness
    if round_idx > 0:
        return {"info_gain": 0, "log": "pwn(local): benign interaction already attempted"}
    stdout, status, image = _run_file_harness(ctx, PwnHarness, PWN_LOCAL_BENIGN_DRIVER, 60)
    run_dir = getattr(ctx.verifier, "run_dir", Path("."))
    log = f"pwn(local): image={image} status={status} out_bytes={len(stdout)}"
    if status != "ok":
        return {"info_gain": 0, "log": log + " (harness did not run)"}
    ev = ctx.verifier.capture(ce.SRC_EXEC, stdout, label=f"pwn-local@{image}")
    m = _CONTEST_FLAG_RE.search(stdout)
    if m and m.group(2).strip() != "None" and ce.matches_format(m.group(2).strip(), ctx.flag_format):
        flag = m.group(2).strip()
        return {"info_gain": 1, "log": log + f" FLAG={flag}",
                "candidate": Candidate(value=flag, confidence=0.9,
                                       evidence_refs=[ev], status="VERIFIED")}
    _log_cyber_gate(run_dir, ctx.cid, "weaponization_required",
                    "local binary gave no benign flag; exploit dev not attempted")
    return {"info_gain": 1 if stdout else 0,
            "log": log + " [cyber] flag behind exploit; weaponization not attempted"}


# ---- pwn (net): session tube through the CM2 broker, [cyber]-gated ------------------

def _log_cyber_gate(run_dir, cid, reason, detail=""):
    """Append a [cyber] weaponization/egress gate event. Logged, never worked around."""
    p = Path(run_dir) / "cyber_gate.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps({"cid": cid, "reason": reason, "detail": detail,
                            "action": "logged_not_bypassed"}) + "\n")


def _benign_pwn_interaction(sess, wall_s):
    """A strictly NON-WEAPONIZING probe: read what the service volunteers and nudge it
    once with a newline. No payload is crafted (that is the gated step). Returns the
    accumulated bytes seen."""
    seen = b""
    try:
        seen += sess.recv(4096, timeout=min(3.0, wall_s))
    except S.SessionError:
        return seen
    try:
        sess.sendline(b"")                       # benign nudge past a prompt
        seen += sess.recv(4096, timeout=min(3.0, wall_s))
    except S.SessionError:
        pass
    return seen


def contest_pwn_solver(ctx, round_idx, info):
    """Attach a session.py tube to the remote target THROUGH the CM2 broker and run only
    non-weaponizing interaction. A flag the service volunteers is a grounded solve; if a
    benign path yields nothing, the exploit-development step is the [cyber] gate — it is
    logged and NOT bypassed, so the challenge ends honestly (StopLoss stops it)."""
    run_dir = getattr(ctx.verifier, "run_dir", Path("."))
    if round_idx > 0:
        return {"info_gain": 0, "log": "pwn: benign interaction already attempted"}
    host, port = ctx.target
    log_dir = Path(run_dir) / "pwn_session"
    try:
        sess = S.Session(remote=(host, port), broker=ctx.broker.address,
                         log_dir=str(log_dir), wall_s=12)
        sess.open()
    except S.BrokerRefused as e:
        _log_cyber_gate(run_dir, ctx.cid, "egress_denied", str(e))
        return {"info_gain": 0, "log": f"pwn: [cyber] egress gate DENIED {host}:{port} ({e})"}
    except S.SessionError as e:
        return {"info_gain": 0, "log": f"pwn: tube connect failed ({e})"}
    try:
        seen = _benign_pwn_interaction(sess, wall_s=10)
    finally:
        sess.close()
    text = seen.decode("utf-8", "replace")
    log = f"pwn: tube via broker -> {host}:{port} recv_bytes={len(seen)}"
    if not seen:
        _log_cyber_gate(run_dir, ctx.cid, "weaponization_required",
                        "no output from benign interaction; exploit dev not attempted")
        return {"info_gain": 0, "log": log + " [cyber] no benign path; weaponization not attempted"}
    ev = ctx.verifier.capture(ce.SRC_TARGET, text, label=f"pwn-tube {host}:{port}")
    m = _FLAG_RE.search(text)
    if m and ce.matches_format(m.group(0), ctx.flag_format):
        flag = m.group(0)
        return {"info_gain": 1, "log": log + f" FLAG={flag}",
                "candidate": Candidate(value=flag, confidence=0.9,
                                       evidence_refs=[ev], status="VERIFIED")}
    # Service reachable but the flag is behind a bug: that is the gated step.
    _log_cyber_gate(run_dir, ctx.cid, "weaponization_required",
                    "benign interaction reached the service but no flag was volunteered")
    return {"info_gain": 1, "log": log + " [cyber] flag behind exploit; weaponization not attempted"}
