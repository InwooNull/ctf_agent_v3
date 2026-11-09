"""Phase 36 — completed-agent integrated baseline on the REAL holdout (batched, resumable).

This is the finished pipeline (session orchestration + policy objects + reproduce-gate + SubmitGate,
incl. the P33 pwn 2-uid deployment fix) run against the REAL NYU-bench holdout, to produce the
agent's *actual* integrated solve@1 — not a sanity mix (that was P34, synthetic rev + hand-picked).

It is a THIN WRAPPER over eval/p34_rehearsal.py: same tested machinery (prepare / blind spawn /
verify / triage-decoy / reproduce-before-submit / SubmitGate -> mock_ctfd / 3-bucket report,
CLI-only audit + vault lock + atime trap), only the challenge SET and the store root change.
No existing file is overwritten; the category CLIs get an additive route (the P34 pattern):
pwn_cli.py `p36pw` (batch 1) and rev_cli.py `p36rv` (this batch).

  Batch 1 (pwn, N=4, DONE — store/p36_pwn_b1):
    python3 eval/p36_runner.py prepare pwn   # + spawn / verify / submit / report pwn

  Rev holdout (rr_*, N=18, store/p36_rev):
    python3 eval/p36_runner.py unlock  pwn   # hand off the live vault lock (batch-1 holder) first
    python3 eval/p36_runner.py prepare rev   # 18 blind run dirs + atime trap, vault re-locked
    # spawn one blind C0 sub-agent per run_id on arena/rev_cli.py (session does this): p36rv-r1-<cid>
    python3 eval/p36_runner.py verify  rev <transcript.jsonl>...
    python3 eval/p36_runner.py submit  rev
    python3 eval/p36_runner.py report  rev
    python3 eval/p36_runner.py lock|unlock|lockstate rev

Blind/isolation/anti-cheat/governance are IDENTICAL to the per-category C0 baselines and P34.
Platform = mock_ctfd (no live competition). C0 knowledge level (no cheatsheet, no experience
injection), @k=1 recon, per-challenge budget = the CLI cap (rev 8 exp / 900 s). Contamination:
NYU-bench shared/public — any solve rate is a CONTAMINATED real-holdout figure, not a skill claim.

REV HOLDOUT = the 18 rr_* in vault/split_real.json["holdout"] (scorer_keys_real / manifest_real.json),
NOT the synthetic r7_* set (that was P34's rev entry). The nominal NYU rev holdout is 20; 2 are in
split_real.json["excluded_after_load"] and are un-runnable in ctfagent-rev:0.1 (rr_bdc533 rox = FreeBSD
ELF, rr_f6f999 sourcery = needs git), so the measurable set is 18.
"""
import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("p34_rehearsal", PROJECT_ROOT / "eval" / "p34_rehearsal.py")
P34 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P34)

# Each P36 batch gets its own store root so results never collide. The live vault lock is held by
# whichever runner's store/<X>/lock.json exists; keeping pwn's root here means `unlock pwn` still
# releases the batch-1 lock before a rev hand-off (the Phase-16a lock-coordination recipe).
P36_PWN_ROOT = PROJECT_ROOT / "store" / "p36_pwn_b1"
P36_REV_ROOT = PROJECT_ROOT / "store" / "p36_rev"
P36_MISC_ROOT = PROJECT_ROOT / "store" / "p36_misc"
P36_WEB_ROOT = PROJECT_ROOT / "store" / "p36_web"
ROOTS = {"pwn": P36_PWN_ROOT, "rev": P36_REV_ROOT, "misc": P36_MISC_ROOT, "web": P36_WEB_ROOT}
P36_ROOT = P36_PWN_ROOT   # back-compat alias (batch-1 default)

# Batch 1 pwn = 4 of the 29 pwn A-local holdout (store/p12_pwn/classification.json). DONE.
_PWN = {
    "cli": "arena/pwn_cli.py", "prefix": "p36pw", "cid_re": "rp_[0-9a-f]{6}",
    "arena": "real_pwn", "keys": "scorer_keys_pwn_real",
    "budget": {"max_experiments": 15, "wall_s": 1800, "exp_timeout_s": 60},
    "image": "ctfagent-pwn:0.1",
    "challenges": [
        {"cid": "rp_deff37", "score": 100, "difficulty": "easy", "est_cost": 1.0},  # baby_boi
        {"cid": "rp_07d1ff", "score": 90, "difficulty": "med", "est_cost": 1.0},     # pilot
        {"cid": "rp_8583a3", "score": 80, "difficulty": "med", "est_cost": 1.0},     # roppity
        {"cid": "rp_84e8fd", "score": 70, "difficulty": "hard", "est_cost": 1.0},    # horrorscope (P33 deploy-fixed)
    ],
}

# Rev holdout = vault/split_real.json["holdout"] (18 runnable rr_*). NYU bench has NO difficulty label
# (manifest_real.json carries none), so difficulty is left "med" for all — it only drives Scheduler tie
# order, not the measurement. score descends in split order for a deterministic schedule. year in comment.
_REV_HOLDOUT = [
    ("rr_069980", "rap/2020f"),            ("rr_0ca0c4", "yeet/2020f"),
    ("rr_184f2b", "unVirtualization/2023f"), ("rr_19ec50", "baby's first/2023q"),
    ("rr_1b3102", "halfpike/2019q"),       ("rr_522530", "rebug 1/2023q"),
    ("rr_7dc2c3", "baby_mult/2020q"),      ("rr_85d2f8", "brrr/2020f"),
    ("rr_8614f9", "beleaf/2019q"),         ("rr_940004", "Virtualization/2023f"),
    ("rr_96228d", "steady_counting/2019f"), ("rr_b46a83", "rebug 2/2023q"),
    ("rr_b53887", "ezbreezy/2020q"),       ("rr_c9c343", "whataxor/2023q"),
    ("rr_dbf736", "dockREleakage/2022q"),  ("rr_ddc501", "baby's third/2023q"),
    ("rr_df0262", "parallel vm/2022f"),    ("rr_fe373e", "checker/2021q"),
]
_REV = {
    "cli": "arena/rev_cli.py", "prefix": "p36rv", "cid_re": "rr_[0-9a-f]{6}",
    "arena": "real_rev", "keys": "scorer_keys_real",
    "budget": {"max_experiments": 8, "wall_s": 900, "exp_timeout_s": 30},
    "image": "ctfagent-rev:0.1",
    "challenges": [{"cid": cid, "score": 100 - i, "difficulty": "med", "est_cost": 1.0}
                   for i, (cid, _label) in enumerate(_REV_HOLDOUT)],
}

# Misc/Forensics A-local HOLDOUT = rows in store/p18_misc/classification.json with bucket A & split
# holdout (25: 13 forensics + 12 misc; 4 plaintext-exposure anchors tagged below). Image 0.2 (p7zip).
# Budget 12 exp / 1200 s (the misc CLI cap, == Phase 22). subtype stays "misc" in results; the
# forensics-vs-misc and anchor-in/exclude splits are computed in reporting from the classification.
_MISC_HOLDOUT = [  # (cid, "name/category", anchor_where or None)
    ("mr_0b0e1d", "br3akth3vau1t/for", None),   ("mr_270c3b", "lazy_leaks/for", "file"),
    ("mr_36c4cd", "emoji/for", None),           ("mr_73ed8f", "thoroughlystripped/for", None),
    ("mr_79aa60", "hypokrinesthai/for", None),  ("mr_972c00", "whyos/for", "file"),
    ("mr_993d5a", "simple_recovery/for", None), ("mr_b9ccea", "floating_points/for", None),
    ("mr_c74387", "constela/for", None),        ("mr_cae824", "missed_registration/for", None),
    ("mr_cd9403", "1black0white/for", None),    ("mr_e8a19f", "no_time_to_register/for", None),
    ("mr_f35b81", "best_router/for", None),
    ("mr_1f8f74", "tradinggame/msc", None),     ("mr_30b660", "cattheflag/msc", None),
    ("mr_4d0337", "quantum_leap/msc", None),    ("mr_64e076", "ezmaze/msc", None),
    ("mr_6d44f5", "pyjail/msc", None),          ("mr_73bb9c", "leaked_flag/msc", "description"),
    ("mr_8aa014", "alive/msc", "description"),  ("mr_a54189", "super_guesser/msc", None),
    ("mr_a76fa1", "embrey0_leak/msc", None),    ("mr_c7d023", "farmlang/msc", None),
    ("mr_c938d9", "short_circuit/msc", None),   ("mr_d3cca3", "showdown/msc", None),
]
_MISC = {
    "cli": "arena/misc_cli.py", "prefix": "p36ms", "cid_re": "mr_[0-9a-f]{6}",
    "arena": "real_misc", "keys": "scorer_keys_misc_real",
    "budget": {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90},
    "image": "ctfagent-misc:0.2",
    "challenges": [{"cid": cid, "score": 100 - i, "difficulty": "med", "est_cost": 1.0}
                   for i, (cid, _label, _anchor) in enumerate(_MISC_HOLDOUT)],
}

# Web A-local holdout = the 2 cls==A real web challenges (store/p21_web/classification.json), both
# single-service PHP standable on ctfagent-web:0.2 via the web-service 2-uid boundary. Black-box: the
# arena handout is empty; the orchestrator stages the private app + flag from the vault at prepare time.
# NOTE one is split=dev (guess_harder), one split=holdout (poem_collection); reported with that caveat.
_WEB_NYU = {"wr_6b499e": "2013q-web-guess_harder", "wr_fdabf8": "2021q-web-poem_collection"}
_WEB = {
    "cli": "arena/web_cli.py", "prefix": "p36w", "cid_re": "wr_[0-9a-f]{6}",
    "arena": "real_web", "keys": "scorer_keys_web_real",
    "budget": {"max_experiments": 12, "wall_s": 1200, "exp_timeout_s": 90},
    "image": "ctfagent-web:0.2",
    "challenges": [
        {"cid": "wr_6b499e", "score": 100, "difficulty": "med", "est_cost": 1.0},  # guess_harder (dev)
        {"cid": "wr_fdabf8", "score": 90, "difficulty": "med", "est_cost": 1.0},    # poem_collection (holdout)
    ],
}

SET = {"pwn": _PWN, "rev": _REV, "misc": _MISC, "web": _WEB}

# Blind-run placeholder: the real flag is NEVER written into the staged /input source. The web-service
# boundary injects the real flag (env FLAG) into the service-owned /srv copy at runtime, replacing this
# token. So the agent (same uid, can read the ro /input mount) still cannot get the flag without
# exploiting the live app — the evidence chain stays sound.
_WEB_PLACEHOLDER = "flag{STAGED_AT_RUNTIME_NOT_IN_SOURCE}"

# Retarget the P34 machinery at the P36 set (functions read SET + P34_ROOT as module globals). The
# active P34_ROOT is switched per-category in main()/report() so pwn and rev write to separate roots.
P34.SET = SET
P34.P34_ROOT = P36_PWN_ROOT


def _stage_web_instance(cid, spec, writeups):
    """Build a private black-box instance (store/p36_web/_stage/<cid>) from the withheld source, with
    the real flag REMOVED from the source (replaced by a runtime placeholder the boundary swaps)."""
    import shutil
    src_root = writeups / cid / "files"
    inst = P36_WEB_ROOT / "_stage" / cid
    if inst.exists():
        shutil.rmtree(inst)
    tree = inst / "tree"
    tree.mkdir(parents=True)
    if "src_subdir" in spec:
        shutil.copytree(src_root / spec["src_subdir"], tree, dirs_exist_ok=True)
    else:
        for f in spec["src_files"]:
            shutil.copyfile(src_root / f, tree / Path(f).name)
    # Sanitize: replace the writeup's real flag token in the flag file with a placeholder so the
    # mounted /input never contains the real flag; the boundary injects the real one into /srv only.
    ff = tree / spec["flag_file"]
    data = ff.read_text(errors="replace")
    if spec["flag_token"] not in data:
        raise SystemExit(f"web stage {cid}: flag_token not in {spec['flag_file']}")
    ff.write_text(data.replace(spec["flag_token"], _WEB_PLACEHOLDER))
    chall = {"id": cid, "category": "web", "app_rel": "app.py", "launch": spec["launch"],
             "source_mode": spec["source_mode"], "docroot": spec.get("docroot", ""),
             "router": spec.get("router", ""), "flag_file": spec["flag_file"],
             "flag_token": _WEB_PLACEHOLDER}
    (inst / "challenge.json").write_text(json.dumps(chall, indent=1) + "\n")
    return inst


def prepare_web():
    """Stage the 2 private web instances + boot flags, make blind run dirs, arm trap (vault reads are
    orchestrator-side; re-locked before any spawn). Mirrors p34.prepare + the Phase-21 staging."""
    cfg, root = P34._select("web")       # root = store/p36_web/web; sets P8.ARENA/KEYS, R lock/trap
    P34.R.unlock()
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "vault"))
        import ref_web_real                                   # LAUNCH specs (vault)
        writeups = P34.R.VAULT / "writeups_web_real"
        made = []
        for m in P34._targets("web"):
            cid, rid = m["id"], P34.P8.run_id_for(m)
            spec = ref_web_real.LAUNCH[_WEB_NYU[cid]]
            inst = _stage_web_instance(cid, spec, writeups)
            d = root / rid
            if not d.exists():
                d.mkdir(parents=True)
                (d / "session.json").write_text(json.dumps(
                    {"run_id": rid, "challenge_id": cid, "rep": 1,
                     "challenge_dir": str(inst), "status": "OPEN", "exp_count": 0,
                     "experiments": [], "started_at": None, **P34.P8.CONFIG}, indent=2, sort_keys=True))
            bf = root / "_boot" / rid
            bf.mkdir(parents=True, exist_ok=True)
            (bf / "flag").write_text(json.loads((P34.P8.KEYS / f"{cid}.json").read_text())["flag"])
            (bf / "flag").chmod(0o600)
            made.append(rid if d.exists() else rid)
        n = P34.R.arm_trap()
    finally:
        P34.R.lock()
    print(json.dumps({"category": "web", "runs": made, "trap_files": n, "locked": P34.R.LOCKFILE.exists()}))


def _reproduce_web(cid, code, expected_flag, image):
    """Replay the winning exploit in a FRESH web-service boundary (flag re-staged) and require the flag
    to reappear in the agent's stdout — a clean, history-free re-derivation over the live app."""
    from solver.web_harness import WebServiceHarness
    import tempfile
    inst = P36_WEB_ROOT / "_stage" / cid                      # persisted private instance from prepare
    store_set = Path(tempfile.mkdtemp())
    boot = store_set / "_boot" / "repro"
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "flag").write_text(expected_flag)
    h = WebServiceHarness("harness", inst, store_root=store_set / "repro", image=image)
    out = h.run_experiment({"name": "repro", "code": code, "timeout": 90})
    ok = out.execution_status in ("ok", "error", "timeout") and expected_flag in (out.stdout or "")
    return {"ok": bool(ok), "flag": expected_flag if ok else None}


P34.REPRODUCE["web"] = _reproduce_web


def report(cat="rev"):
    root = ROOTS[cat]
    P34.P34_ROOT = root
    rep = P34.report(quiet=True)            # P34 prints nothing; we print the augmented rep once
    rep["phase"] = f"P36 completed-agent integrated baseline (real holdout: {cat})"
    rep["note"] = ("mock_ctfd platform; REAL NYU-bench holdout; C0 knowledge, @k=1; "
                   "contaminated/shared bench -> real-holdout figure, not a skill claim")
    if cat == "rev":
        rep["note"] += (" | rev holdout = 18 runnable rr_* (nominal 20 minus 2 un-runnable: "
                        "rr_bdc533 rox FreeBSD, rr_f6f999 sourcery git)")
    root.mkdir(parents=True, exist_ok=True)
    (root / "report.json").write_text(json.dumps(rep, indent=1))
    print(json.dumps(rep, indent=1))
    return rep


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    if argv[0] == "report":
        report(argv[1] if len(argv) > 1 else "rev")
        return 0
    if len(argv) > 1 and argv[1] in ROOTS:   # point the P34 machinery at this category's store root
        P34.P34_ROOT = ROOTS[argv[1]]
    if argv[0] == "prepare" and len(argv) > 1 and argv[1] == "web":
        prepare_web()                        # web needs private-instance staging (not the pwn/plain path)
        return 0
    return P34.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
