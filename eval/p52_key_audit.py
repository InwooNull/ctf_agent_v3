"""Phase 52 KEY-AUDIT (ORCHESTRATOR-ONLY, sanctioned) for mr_30b660.

Reads the scorer key + manifest at orchestrator level (NOT a solver) to cross-check a
reproducible evidenced-candidate-vs-key MISMATCH. The solver stays blind; this does a
sanctioned unlock -> read -> re-lock + re-arm of the vault, so blindness for any solver is
restored on exit. Run it YOURSELF in the terminal (the auto-mode classifier blocks an
agent-issued vault unlock as 'Security Weaken'):

    ! cd ~/ctf_agent_v3 && python3 eval/p52_key_audit.py

It prints: the manifest-mapped original challenge name/source, the scorer key value, and
the agent's own evidenced candidate (from its dev run output) — for human cross-check
against the public canonical CSAW challenge. Nothing is written to a solver-visible path.
"""
import sys, json, re, os, importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
_s = importlib.util.spec_from_file_location("p51", PROJECT_ROOT / "eval" / "p51_cycle.py")
m = importlib.util.module_from_spec(_s); _s.loader.exec_module(m)
R, KEYS, VAULT = m.R, m.KEYS, m.R.VAULT
CID = "mr_30b660"


def _candidates(run_dir):
    vals = []
    for name in ("harness/candidates.jsonl", "harness/state.json", "session.json"):
        p = Path(run_dir) / name
        if p.is_file():
            vals += re.findall(r'[A-Za-z0-9_]{2,}\{[^}]{3,}\}', p.read_text(errors="replace"))
    return sorted(set(vals))


def main():
    cand = _candidates(PROJECT_ROOT / "store" / "p51_misc" / ("p51c1-" + CID))
    R.unlock()
    try:
        manifest, src = {}, None
        for mn in ("manifest_misc_real.json", "manifest_misc.json"):
            mp = VAULT / mn
            if not mp.is_file():
                continue
            md = json.loads(mp.read_text())
            if CID in md:
                manifest, src = md[CID], mn
            elif isinstance(md.get("challenges"), list):
                hit = next((c for c in md["challenges"] if c.get("id") == CID or c.get("cid") == CID), {})
                if hit:
                    manifest, src = hit, mn
            if manifest:
                break
        kp = KEYS / (CID + ".json")
        key = json.loads(kp.read_text()) if kp.is_file() else {"MISSING": str(kp)}
    finally:
        R.arm_trap()
        R.lock()
    out = {
        "cid": CID,
        "manifest_source_file": src,
        "manifest_entry": manifest,
        "scorer_key": key,
        "agent_evidenced_candidates": cand,
        "vault_mode_after": oct(os.stat(VAULT).st_mode & 0o777),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
