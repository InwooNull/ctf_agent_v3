"""Phase 21 re-classification: apply the ctfagent-web:0.2 capability (single-service PHP via
`php -S`, plus py3 Flask) to the Phase 20 web A/B/C table and report the updated counts.

Reads store/p20_web/classification.json (NOT the vault) and promotes a Phase 20 "C (runtime not in
image)" challenge to "A" iff it is a SINGLE-service app whose only runtime need is PHP or py3-Flask
(no DB server, no node, no java/tomcat, no python2, no multi-container, no docker socket) AND it is
not held back by a per-challenge runtime caveat (encoded below, each with a reason). Everything else
keeps its Phase 20 class. 0.2 is a fallback-safe superset of 0.1: if 0.2 is unavailable the whole
A set simply reverts to Phase 20's (A=0).

  python3 eval/real_web_reclassify.py      # -> store/p21_web/classification.json

No flags, no vault reads; this is a capability re-labelling of the public classification only.
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
P20 = PROJECT_ROOT / "store" / "p20_web" / "classification.json"
OUT = PROJECT_ROOT / "store" / "p21_web"

_DB = {"mysql", "mariadb", "mongo", "postgres", "redis"}

# Caveats: challenges that LOOK php/flask-single-service by the Phase 20 `needs` heuristic but do NOT
# naturally run on ctfagent-web:0.2 (verified by reading the source in Phase 21). They stay C with a
# recorded reason instead of being promoted.
CAVEATS = {
    "2016q-web-mfw": "intended bug is PHP 7.0 assert()-string code-eval (zend.assertions=1); assert() "
                     "stopped evaluating string arguments in PHP 8, and 0.2 ships PHP 8.2 (bookworm) "
                     "-> the RCE does not reproduce. php7+apache only.",
    "2014f-web-webroot": "needs apache vhost (test2.php webroot disclosure) + the mcrypt extension "
                         "(removed in PHP 7.2+) + AMF/DES-ECB SQLi; not a single `php -S` app.",
    "2017q-web-littlequery": "server needs MySQL (mysqli in db.php) AND a node 'runtime' sandbox "
                             "(query.php spawns node); multi-dependency, not a single `php -S` app.",
}


def _needs_tags(needs):
    php = "php" in needs
    flask = any(n.startswith("py-framework") and "flask" in n for n in needs)
    db = any(d in n for n in needs for d in _DB)
    node = "node" in needs
    java = any("tomcat" in n or "java" in n for n in needs)
    py2 = "python2" in needs
    return php, flask, db, node, java, py2


def reclassify(c):
    out = {}
    for cid, r in c.items():
        needs = set(r.get("needs", []))
        php, flask, db, node, java, py2 = _needs_tags(needs)
        new, reason = r["cls"], r.get("reason", "")
        if r["cls"] == "C":
            eligible = (php or flask) and not db and not node and not java and not py2 and not r.get("multi")
            if eligible and r["nyu_id"] not in CAVEATS:
                new = "A"
                reason = ("single-service " + ("PHP (php -S)" if php else "py3 Flask") +
                          " -> standable on ctfagent-web:0.2 web-service 2-uid boundary")
            elif eligible and r["nyu_id"] in CAVEATS:
                reason = "stays C: " + CAVEATS[r["nyu_id"]]
        out[cid] = {**r, "cls": new, "reason": reason,
                    "promoted_from_C": (r["cls"] == "C" and new == "A")}
    return out


def main():
    if not P20.exists():
        raise SystemExit("store/p20_web/classification.json missing; run Phase 20 first")
    c = json.loads(P20.read_text())
    out = reclassify(c)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "classification.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    counts = {"A": 0, "B": 0, "C": 0}
    for r in out.values():
        counts[r["cls"]] += 1
    promoted = sorted(r["nyu_id"] for r in out.values() if r.get("promoted_from_C"))
    print("image=ctfagent-web:0.2 (fallback 0.1 -> A=0)")
    print("COUNTS", counts, "| promoted C->A:", promoted)
    for cls in ("A", "B", "C"):
        print(f"\n==== {cls} ({counts[cls]}) ====")
        for cid, r in sorted(out.items(), key=lambda kv: (kv[1]["split"], kv[1]["nyu_id"])):
            if r["cls"] == cls:
                print(f"  {cid} {r['split']:7} {r['nyu_id']:26} :: {r['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
