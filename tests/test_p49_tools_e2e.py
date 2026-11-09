"""Phase 49a: the user-approved misc:0.5 tools work in-sandbox with isolation preserved —
tesseract (OCR), OpenCV (cv2), stegseek + wordlist. Gated on ctfagent-misc:0.5 (docker, no
live solver / no tokens). Each experiment runs --network none, read-only root, non-root.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from solver.misc_harness import MiscHarness, MISC_IMAGE_FINALS, MISC_WORDLIST  # noqa: E402
from tools import sandbox  # noqa: E402

_DOCKER = sandbox.docker_available() and sandbox.image_available(MISC_IMAGE_FINALS)


def _chal(tmp):
    d = Path(tmp) / "mr_tools"
    d.mkdir(parents=True)
    (d / "challenge.json").write_text(json.dumps(
        {"id": "mr_tools", "category": "misc", "files": [], "description": "x", "flag_format": "flag{...}"}))
    return d


OCR_CV2 = r'''
import subprocess, os, numpy as np, cv2
img = np.full((60, 440, 3), 255, np.uint8)
cv2.putText(img, "OCRFLAG42", (10, 44), cv2.FONT_HERSHEY_SIMPLEX, 1.3, (0, 0, 0), 3)
cv2.imwrite("/work/t.png", img)
print("CV2", cv2.__version__)
r = subprocess.run(["tesseract", "/work/t.png", "stdout"], capture_output=True, text=True)
print("OCR", r.stdout.replace(" ", "").strip().upper())
'''

STEGSEEK = r'''
import subprocess, numpy as np, cv2
cv2.imwrite("/work/c.bmp", np.random.randint(0,255,(256,256,3),dtype="uint8"))
open("/work/s.txt","w").write("STEGSEEK_RUNTIME_OK")
subprocess.run(["steghide","embed","-cf","/work/c.bmp","-ef","/work/s.txt",
                "-p","stegseek_e2e_seed_pass","-q"], check=True)
r = subprocess.run(["stegseek","--crack","/work/c.bmp","''' + MISC_WORDLIST + r'''",
                    "/work/out","-xf","/work/rec.txt"], capture_output=True, text=True)
print("STEGSEEK_RC", r.returncode)
print("RECOVERED", open("/work/rec.txt").read().strip() if __import__("os").path.exists("/work/rec.txt") else "NONE")
'''

EGRESS = r'''
import socket
try:
    socket.create_connection(("8.8.8.8",53),1.0); print("EGRESS_OPEN")
except OSError:
    print("EGRESS_BLOCKED")
'''


@unittest.skipUnless(_DOCKER, f"{MISC_IMAGE_FINALS} not built locally")
class TestTools05(unittest.TestCase):
    def _run(self, tmp, code):
        h = MiscHarness("t", _chal(tmp), store_root=Path(tmp) / "store", image=MISC_IMAGE_FINALS)
        return h.run_experiment({"name": "e", "code": code, "timeout": 120})

    def test_ocr_and_cv2(self):
        with tempfile.TemporaryDirectory() as t:
            o = self._run(t, OCR_CV2)
            self.assertEqual(o.execution_status, "ok", o.stdout)
            self.assertIn("CV2 4.", o.stdout)                 # cv2 imported + basic op
            self.assertIn("OCRFLAG42", o.stdout)              # tesseract read the drawn text

    def test_stegseek_cracks_known_passphrase(self):
        with tempfile.TemporaryDirectory() as t:
            o = self._run(t, STEGSEEK)
            self.assertEqual(o.execution_status, "ok", o.stdout)
            self.assertIn("RECOVERED STEGSEEK_RUNTIME_OK", o.stdout)

    def test_isolation_preserved_and_no_egress(self):
        with tempfile.TemporaryDirectory() as t:
            h = MiscHarness("t2", _chal(t), store_root=Path(t) / "store", image=MISC_IMAGE_FINALS)
            c = h.sandbox_config["container"]
            self.assertEqual(c["network"], "none")
            self.assertTrue(c["read_only_root"])
            self.assertEqual(c["cap_drop"], ["ALL"])
            self.assertTrue(c["no_new_privileges"])
            o = h.run_experiment({"name": "net", "code": EGRESS, "timeout": 30})
            self.assertIn("EGRESS_BLOCKED", o.stdout)


if __name__ == "__main__":
    unittest.main()
