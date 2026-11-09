"""Public scorer/checker for a synthetic mlsec challenge (numpy only).

check(artifact_path, chal_dir) -> bool : True iff the submitted artifact satisfies
the challenge's success condition. Holds NO flag — the scorer adds the flag on pass.
"""
import json
import numpy as np
from pathlib import Path


def _load(chal_dir):
    d = np.load(Path(chal_dir) / "data.npz")
    meta = json.loads((Path(chal_dir) / "meta.json").read_text())
    return d, meta


def check(artifact_path, chal_dir):
    d, meta = _load(chal_dir)
    art = np.load(artifact_path)
    st = meta["subtype"]
    if st == "adversarial-example":
        W, b, x0 = d["W"], d["b"], d["x0"]
        art = np.asarray(art, dtype=float).reshape(x0.shape)
        if np.max(np.abs(art - x0)) > meta["eps"] + 1e-6:
            return False
        logits = W @ art + b
        return int(np.argmax(logits)) == int(meta["target_class"])
    if st == "scoring-threshold":
        w, b, base = d["w"], float(d["b"]), d["base"]
        art = np.asarray(art, dtype=float).reshape(base.shape)
        if np.max(np.abs(art - base)) > meta["budget"] + 1e-6:
            return False
        return float(w @ art + b) >= meta["threshold"]
    if st == "weight-recovery":
        secret = d["secret"]
        art = np.asarray(art, dtype=float).reshape(secret.shape)
        return bool(np.allclose(np.round(art).astype(int), secret))
    return False
