"""Surface — the set of files the growth loop is ALLOWED to self-modify, with atomic,
hash-verified snapshot/rollback (Phase 44c).

The managed surface is ONLY the autonomy-boundary-AUTO files: skill-pack cheatsheets /
routing (skills/<cat>/*.md), the experience store, and the growth budget config. It must
NEVER include a governance/isolation file (SubmitGate, verifier, FWS guard, web/pwn
service, sandbox config, vault splits) — those are hashed in growth/governance_baseline.txt
and are not part of any Surface.

snapshot() captures exact bytes (and absence) of every managed file; restore() writes
them back and then re-hashes everything, raising RollbackError unless every file is
byte-identical to the snapshot (no partial restore, no residue). restore() is idempotent,
so a restore interrupted by a crash can simply be re-run from the same snapshot.
"""
import hashlib
from pathlib import Path


class RollbackError(RuntimeError):
    pass


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


class Surface:
    def __init__(self, files):
        self.files = [Path(f) for f in files]

    def snapshot(self):
        """{path: {present, sha256, bytes}} for every managed file (bytes=None if absent)."""
        snap = {}
        for p in self.files:
            if p.is_file():
                b = p.read_bytes()
                snap[str(p)] = {"present": True, "sha256": sha256_bytes(b), "bytes": b}
            else:
                snap[str(p)] = {"present": False, "sha256": None, "bytes": None}
        return snap

    def hashes(self):
        """{path: sha256|None} — the current state, for drift comparison."""
        return {str(p): (sha256_bytes(p.read_bytes()) if p.is_file() else None) for p in self.files}

    def restore(self, snap):
        """Restore every managed file to the snapshot, then VERIFY byte-identity by
        sha256. Raises RollbackError on any mismatch (partial restore is a hard error)."""
        for p in self.files:
            rec = snap[str(p)]
            if rec["present"]:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(rec["bytes"])
            elif p.is_file():
                p.unlink()                      # it did not exist at snapshot time -> remove
        now = self.snapshot()
        for key, rec in snap.items():
            cur = now[key]
            if cur["present"] != rec["present"] or cur["sha256"] != rec["sha256"]:
                raise RollbackError(
                    f"rollback verification failed for {key}: "
                    f"want present={rec['present']} sha={rec['sha256']}, "
                    f"got present={cur['present']} sha={cur['sha256']}")
        return True

    @staticmethod
    def snapshot_hashes(snap):
        return {k: v["sha256"] for k, v in snap.items()}

    # --- durable snapshots (survive a crash, for mid-improve resume) --------
    @staticmethod
    def write_snapshot(snap, dirpath):
        """Persist a snapshot to disk (manifest + raw blobs) BEFORE a change is applied,
        so a crash mid-change can be undone exactly on resume."""
        import json
        d = Path(dirpath)
        d.mkdir(parents=True, exist_ok=True)
        manifest = {}
        for i, (k, rec) in enumerate(sorted(snap.items())):
            blob = None
            if rec["present"]:
                blob = f"{i}.bin"
                (d / blob).write_bytes(rec["bytes"])
            manifest[k] = {"present": rec["present"], "sha256": rec["sha256"], "blob": blob}
        (d / "manifest.json").write_text(json.dumps(manifest))

    @staticmethod
    def read_snapshot(dirpath):
        import json
        d = Path(dirpath)
        manifest = json.loads((d / "manifest.json").read_text())
        snap = {}
        for k, rec in manifest.items():
            b = (d / rec["blob"]).read_bytes() if rec["present"] else None
            snap[k] = {"present": rec["present"], "sha256": rec["sha256"], "bytes": b}
        return snap
