# AI/ML model-file security (mlsec) — the model-file axis of the AI category

Our AI category (docs/ai_category.md) began injection-centric (guard bypass, RAG,
agent chains). The other large axis of real AI CTFs is **model-file / adversarial-ML**:
challenges that hand you a model (`.pt` / `.safetensors` / `.onnx`) or a scoring
server and ask you to defeat its weights, inference, or threshold. ACDC's *Damaged
fingerprint* (ML scoring) and *Clear_Picture* (vision/ML) were this class and we did
not solve them. This sub-harness adds the plumbing. (Redesigned in our own terms; no
external skill code was copied.)

**Scope / ethics.** Targets are local synthetic challenges or an authorized CTF only;
no live access. Submission goes through the Phase-25 SubmitGate; evidence is required.

## Subtypes (success = flag emitted / threshold passed)

- **weight-recovery / perturbation** — recover hidden weights or inputs by inverting
  the provided model/observations (e.g. `obs = W·secret` → least-squares).
- **adversarial-example** — craft an input within an L∞ budget that the classifier
  misreads as a target class (FGSM / PGD).
- **model-inversion / extraction** — reconstruct training data or internals by query.
- **membership-inference** — decide whether a sample was in the training set.
- **scoring-threshold bypass** — drive a server scorer's output past its threshold T
  on a crafted sample (the *Damaged fingerprint* shape).

## Image `ctfagent-mlsec:0.1`

`python:3.12-slim-bookworm` + `libgomp1` + pip `torch==2.4.1+cpu`, `onnx==1.16.2`,
`onnxruntime==1.19.2`, `scikit-learn==1.5.2`, `numpy` (resolved to 2.5.4 by deps —
all libraries import together fine). CPU-only (no CUDA). Network is used ONLY at build
time; at run time the sandbox forces `--network none`, read-only root, non-root uid,
rlimits. Versions: `docker/mlsec_versions.txt`. Build:
`docker build -f docker/Dockerfile.mlsec -t ctfagent-mlsec:0.1 .`
(torch autograd verified working under the full lockdown.) The mlsec container profile
raises the memory limit to **2g** (torch needs far more than the 256m crypto default).

## Harness `solver/mlsec_harness.py`

Reuses the CryptoHarness container-run plumbing unchanged (every attack runs in the
mlsec image, isolated), then adds a scorer-based evidence model:

- the attack runs in-container and writes an **artifact** (perturbed input / recovered
  value) into the run's `/work` bind mount; the flag is **not** mounted, so the attack
  code can never read it;
- a trusted **scorer** holds the flag and confirms success:
  `RemoteScorer.score(artifact) -> {passed, flag, detail}`, with `MockScorer`
  (local, deterministic, runs a public `checker` + injected vault flag) and
  `ChalsrvScorer` (wraps `connector.chalsrv` for a live/recorded server);
- a candidate is **VERIFIED** only when the scorer accepted an artifact a real
  container experiment produced (evidence = that experiment); a passing verdict with
  no real run is **UNVERIFIED** (FWS), a non-passing artifact yields no candidate.

## Synthetic dev set (`vault/gen_mlsec.py`, deterministic)

`arena/mlsec/<sid>/` holds public `data.npz` + `meta.json` + `checker.py` +
`challenge.json` (no flag); flags live only in `vault/mlsec_flags.json`.

- `mls_s1` adversarial-example — linear classifier; targeted FGSM within eps.
- `mls_s2` scoring-threshold — linear scorer; gradient ascent to pass T within budget.
- `mls_s3` weight-recovery — recover the integer secret from `obs = W·secret` (lstsq).

## Reference proof (`vault/ref_mlsec.py`, non-LLM, deterministic)

Solves all three in-container, scores host-side, and asserts: SOLVED with evidence
chain, isolation (container + network guaranteed), the FWS/UNVERIFIED branch, SubmitGate
governance (sub-agent blocked, orchestrator submits, flag sha only), and zero zombie
containers. `python3 vault/ref_mlsec.py` → `PROOF mlsec OK`.

## Tests

`tests/test_mlsec.py`: scorer + candidate/evidence branches + classifier wiring (no
docker), plus one container e2e (real torch FGSM) that uses a test flag and skips if
the image is absent.
