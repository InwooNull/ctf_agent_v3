"""CM10 — the contest-mode growth lever (grow from real-competition experience).

This is the contest analogue of the Phase-44/51 blind growth loop, built by REUSING the
existing pieces (growth.diagnoser, growth.experience, growth.surface, orchestrator.
contest_log). It adds NO new solver, runner, verifier, or governance surface.

Three hard invariants, each enforced by a CM10 test:

1.  NO FALSE LESSONS (CM10a). Only a VERIFIED contest solve is promoted into the contest
    experience store. A CANDIDATE_UNVERIFIED flag (a guess / no evidence chain — the
    contest analogue of FWS) and a diagnosed failure are NEVER promoted. The VERIFIED
    filter reads the authoritative contest verdict directly, independent of any upstream
    `solved` boolean, so a mislabelled success cannot leak in.

2.  BENCH MEASUREMENT PURITY (CM10a). Promotion writes ONLY to
    store/contest/experience_contest.jsonl (source="contest", via
    orchestrator.contest_log.ContestExperience). The blind bench stores
    store/experience_*.jsonl are never opened for writing — contest learning can never
    contaminate blind measurement. Diagnosed tool/harness gaps are routed to a
    human-gate needs.jsonl, never auto-applied.

3.  (CM10b/c, added in later steps) injection draws ONLY from the contest store, and any
    cumulative injection that regresses the blind bench holdout is rolled back
    atomically + hash-verified.

Blindness: a promoted record is distilled from the agent's OWN contest trace (the winning
technique fingerprint, the cited evidence id, the verified verdict) and carries no flag
(no_flag=True). The diagnoser reads only trace signals + the verdict, never a key.
"""
import json
from pathlib import Path

from growth.diagnoser import Diagnoser, is_auto
from growth import experience as X
from orchestrator.contest_log import ContestExperience
from solver.contest_evidence import VERIFIED

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STORE_ROOT = PROJECT_ROOT / "store"
CONTEST_EXP_PATH = DEFAULT_STORE_ROOT / "contest" / "experience_contest.jsonl"
# The blind bench stores. CM10 NEVER writes these; a test asserts they are byte-identical
# across a promote. Listed here so the guarantee is explicit and auditable.
BENCH_STORES = ("experience_misc.jsonl", "experience_ai.jsonl", "experience_misc.jsonl")


# --- a thin contest-result -> record shim (no new public type) --------------
class _ResultShim:
    """Exposes exactly the attributes growth.experience.build_record reads, from a plain
    contest result dict. Never carries a flag."""

    def __init__(self, result):
        sig = dict(result.get("signals") or {})
        sig.setdefault("transcript_excerpt", result.get("transcript_excerpt", ""))
        sig.setdefault("winning_exp", result.get("winning_exp", ""))
        self.signals = sig
        self.cid = result.get("cid", "")
        self.category = result.get("category", "") or "web"
        self.subtype = result.get("subtype") or result.get("category") or "web"
        self.winning_exp = result.get("winning_exp", "")


def _is_verified(result):
    """A contest solve the loop is allowed to learn from. Reads the authoritative verdict
    directly (not a `solved` boolean) so a wrongly-flagged success cannot be promoted."""
    return result.get("verdict") == VERIFIED


def verified_solves(results):
    """The ONLY contest results promotable as experience: verdict == VERIFIED. A
    CANDIDATE_UNVERIFIED (guess / no-evidence, the contest FWS analogue) is excluded."""
    return [r for r in results if _is_verified(r)]


# =============================== CM10a: diagnose =============================
# JSONL human-gate sink for contest (the contest analogue of growth/requests.md). A
# non-AUTO diagnosis (tool_gap / harness_bug / cyber_blocked / human_grade / fws /
# ambiguous) is appended here for a human; it is NEVER auto-applied by the loop.
def write_needs(diagnoses, needs_path):
    """Append every NON-AUTO contest diagnosis to needs.jsonl. AUTO buckets are omitted
    (they are the loop's own lane, gated later). cyber_blocked is deduped to one entry
    per cid across the file. Returns the records actually written this call."""
    needs_path = Path(needs_path)
    needs_path.parent.mkdir(parents=True, exist_ok=True)
    existing_keys = set()
    if needs_path.is_file():
        for line in needs_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            existing_keys.add((rec.get("bucket"), rec.get("cid")))
    wrote = []
    with needs_path.open("a", encoding="utf-8") as f:
        for d in diagnoses:
            if is_auto(d.get("bucket", "")):
                continue
            key = (d.get("bucket"), d.get("cid"))
            if d.get("bucket") == "cyber_blocked" and key in existing_keys:
                continue
            existing_keys.add(key)
            rec = {"source": "contest", "cid": d.get("cid"), "bucket": d.get("bucket"),
                   "disposition": d.get("disposition"), "reason": d.get("reason", ""),
                   "confidence": d.get("confidence"), "gate": "human"}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            wrote.append(rec)
    return wrote


def diagnose_contest(fail_results, needs_path, judge=None):
    """Diagnose FAILED contest results and route non-AUTO buckets to needs.jsonl.

    fail_results: contest result dicts that did NOT verify (verdict != VERIFIED), each a
    RunOutcome-like with .signals used by the 44b/46b rule table.
    Returns (diagnoses, needs_written). Reuses the frozen diagnoser; writes no skill."""
    from growth.loop import RunOutcome
    runs = []
    for r in fail_results:
        sig = dict(r.get("signals") or {})
        runs.append(RunOutcome(cid=r.get("cid", ""), outcome=r.get("verdict", "GIVE_UP"),
                               solved=False, category=r.get("category", ""), signals=sig))
    diagnoses = Diagnoser(judge=judge).diagnose(runs)
    needs_written = write_needs(diagnoses, needs_path)
    return diagnoses, needs_written


# =============================== CM10a: promote =============================
def promote_contest(results, store_root=DEFAULT_STORE_ROOT, recipes=None):
    """Promote VERIFIED contest solves into store/contest/experience_contest.jsonl.

    - Only verdict==VERIFIED results are considered (no guess / no FWS false positive).
    - Records are distilled with growth.experience.build_record (no_flag=True), tagged
      source="contest", and deduped by (subtype, technique fingerprint) against the
      existing contest store.
    - Written ONLY through ContestExperience (the contest store); the blind bench stores
      are never touched.

    Returns the list of records actually appended (new, non-duplicate)."""
    recipes = recipes or {}
    store = ContestExperience(store_root)
    existing = X.load((store.path,))
    have = {X._fp_hash(r.get("subtype", ""), r.get("technique", [])) for r in existing}
    written = []
    for res in verified_solves(results):
        shim = _ResultShim(res)
        rec = X.build_record(shim, transcript_text=shim.signals.get("transcript_excerpt", ""),
                             recipe=recipes.get(res.get("cid")))
        rec["cid"] = res.get("cid", "")           # keep the solved cid (source is force-tagged below)
        key = X._fp_hash(rec.get("subtype", ""), rec.get("technique", []))
        if key in have:
            continue
        have.add(key)
        written.append(store.add(rec))            # store.add force-tags source="contest"
    return written


def load_contest_experience(store_root=DEFAULT_STORE_ROOT):
    """All promoted contest pattern records (schema-shaped; flat legacy rows skipped)."""
    return X.load((Path(store_root) / "contest" / "experience_contest.jsonl",))


# =============================== CM10b: reinjection =========================
# Promoted contest patterns are rendered into skills/<pack>/experience_contest.md, which
# skill_pack.load_pack(full=True) concatenates into the NEXT contest solve's pack. The
# file name is distinct from the bench experience.md, and the ONLY source is the contest
# store (load_contest_experience) — a bench record can never reach a contest injection.
# skill_pack.py is governance-frozen; this needs no change to it (it just globs *.md).
from orchestrator.contest_log import pack_name

INJECTION_BASENAME = "experience_contest.md"
INJECTION_LOG = "injection_log.jsonl"
SKILLS_DIR = PROJECT_ROOT / "skills"


def render_contest_injection(patterns):
    """Render promoted CONTEST patterns as a skills/<pack>/experience_contest.md body.
    Deterministic, flag-free (records are no_flag). Empty -> a minimal no-op header."""
    lines = [
        "# Verified contest solve patterns (contest experience)",
        "",
        "Methodology distilled from this agent's own VERIFIED contest solves (source=",
        "contest only — never the blind bench store). Background only: which technique",
        "family fit which observation. No flag, no ready answer — you still derive and",
        "verify every flag against the real target/checker. Confirm the precondition",
        "before reaching for a tool.",
        "",
    ]
    for rec in sorted(patterns, key=lambda r: (r.get("subtype", ""), str(r.get("technique", [])))):
        tech = ", ".join(rec.get("technique", [])) or "(observe-first)"
        lines.append(f"- **{rec.get('subtype','?')}** ({rec.get('category','?')}): {tech}")
        lines.append(f"  - {rec.get('recipe','')}")
        lines.append(f"  - knew it worked: {rec.get('signals','')}")
    return "\n".join(lines) + "\n"


def _log_injection(store_root, entry):
    path = Path(store_root) / "contest" / INJECTION_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def inject_contest(store_root=DEFAULT_STORE_ROOT, categories=None, skills_root=SKILLS_DIR,
                   clock=None):
    """Render the contest experience store into skills/<pack>/experience_contest.md for
    each pack that has promoted patterns, so the NEXT contest solve's skill_pack carries
    them. The injection source is the contest store ONLY (bench never mixed in).

    categories: optional iterable of contest category tokens to restrict to (e.g. ["web"]).
    Returns {pack: {"file": path, "n_patterns": int, "fp": [hashes]}} and logs each write
    to store/contest/injection_log.jsonl.
    """
    import time as _time
    clock = clock or _time.time
    records = load_contest_experience(store_root)       # CONTEST store only
    # group by the skills/<pack> directory name (rev -> reverse, etc.)
    by_pack = {}
    for rec in records:
        pack = pack_name(rec.get("category", "") or "")
        if categories is not None and rec.get("category") not in set(categories) \
                and pack not in set(categories):
            continue
        by_pack.setdefault(pack, []).append(rec)
    out = {}
    for pack, patterns in by_pack.items():
        pack_path = Path(skills_root) / pack
        if not (pack_path / "SKILL.md").is_file():
            # no knowledge pack for this category -> skip (a missing pack degrades to C0)
            continue
        target = pack_path / INJECTION_BASENAME
        target.write_text(render_contest_injection(patterns), encoding="utf-8")
        fps = [X._fp_hash(p.get("subtype", ""), p.get("technique", [])) for p in patterns]
        entry = {"ts": round(clock(), 6), "pack": pack, "file": str(target),
                 "n_patterns": len(patterns), "fp": fps, "source": "contest"}
        _log_injection(store_root, entry)
        out[pack] = {"file": str(target), "n_patterns": len(patterns), "fp": fps}
    return out


# =============================== CM10c: bench drift gate ====================
# The cumulative contest injection must not regress the BLIND bench holdout. The holdout
# is graded --network none / blind (holdout_eval is injected; it internally uses the
# existing blind runner + unlock->grade->relock, never a key). If applying the injection
# strictly drops the holdout score, the injection is rolled back ATOMICALLY and
# HASH-VERIFIED via growth.surface.Surface (the same mechanism the 44c improver uses).
#
# HONEST SCOPE: the effective blind holdout is THIN (n≈2 after exclusions). This gate is
# therefore a MINIMAL drift guard only — it reliably catches a gross regression but cannot
# validate a large cumulative learning. Flagged provisional until the holdout is re-sourced.
from growth.surface import Surface

HOLDOUT_PROVISIONAL = {
    "n_effective": 2,
    "status": "provisional",
    "note": ("blind holdout thin (n≈2 after exclusions): minimal drift guard only — "
             "catches gross regression, cannot validate large cumulative learning. "
             "Provisional until the holdout is re-sourced."),
}


def _score(res):
    return sum(1 for v in res.values() if v)


def drift_gate(surface_files, holdout_eval, apply_fn, clock=None):
    """Blind-holdout no-strict-drop gate around a cumulative injection.

    surface_files : the files the injection writes (the managed drift surface).
    holdout_eval()->{cid:solved} : the BLIND, graded bench holdout (no key read here).
    apply_fn()     : performs the injection (writes the surface files). Called AFTER the
                     baseline holdout is measured, so before/after bracket exactly it.

    Measures the holdout BEFORE (pre-injection surface) and AFTER applying. Keeps the
    injection iff after >= before (no STRICT drop; conservative on any drop). On a drop,
    restores the pre-injection snapshot (atomic, hash-verified) and reports it rolled back.
    Returns a result dict incl. the HOLDOUT_PROVISIONAL honest-scope flag.
    """
    import time as _time
    clock = clock or _time.time
    surface = Surface(list(surface_files))
    snap = surface.snapshot()                    # pre-injection state (files likely absent)
    before = _score(holdout_eval())
    apply_fn()                                   # cumulative injection applied
    after = _score(holdout_eval())
    kept = after >= before
    rolled_back = False
    hash_verified = True
    if not kept:
        hash_verified = surface.restore(snap)    # raises RollbackError unless byte-identical
        rolled_back = True
    result = {
        "ts": round(clock(), 6), "kept": kept, "rolled_back": rolled_back,
        "holdout_before": before, "holdout_after": after, "delta": after - before,
        "hash_verified": bool(hash_verified),
        "reason": ("kept: holdout did not strictly drop" if kept
                   else "rollback: holdout strictly dropped (conservative on any drop)"),
        "holdout_scope": dict(HOLDOUT_PROVISIONAL),
    }
    return result


def bench_regression_gate(store_root=DEFAULT_STORE_ROOT, *, holdout_eval,
                          skills_root=SKILLS_DIR, categories=None, clock=None):
    """Convenience wrapper: gate the contest injection (inject_contest) over the whole
    experience_contest.md drift surface against the blind holdout, logging the verdict to
    store/contest/drift_gate.jsonl. Returns the drift_gate result (+ the injection map on
    keep)."""
    targets = injection_targets(skills_root)
    applied = {}

    def _apply():
        applied.update(inject_contest(store_root=store_root, categories=categories,
                                      skills_root=skills_root, clock=clock))

    res = drift_gate(targets, holdout_eval, _apply, clock=clock)
    res["injection"] = applied if res["kept"] else {}
    log = Path(store_root) / "contest" / "drift_gate.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(res, ensure_ascii=False) + "\n")
    return res


def injection_targets(skills_root=SKILLS_DIR):
    """Every skills/<pack>/experience_contest.md path (present or not) — the CM10c drift
    surface. One per existing pack dir that has a SKILL.md."""
    out = []
    root = Path(skills_root)
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        if (d / "SKILL.md").is_file():
            out.append(d / INJECTION_BASENAME)
    return out
