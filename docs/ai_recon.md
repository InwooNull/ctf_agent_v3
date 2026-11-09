# Phase 32 — AI/ML-security challenge sourcing reconnaissance (2026-10-31)

Recon ONLY (no loading, no measurement, nothing cloned — public pages read). Question:
can we source public, authorized AI/ML-security CTF challenges that our stack reproduces
OFFLINE for a first real mlsec/AI C0 baseline? Our constraints: image `ctfagent-mlsec:0.1`
= torch + onnx + sklearn + numpy (NO TensorFlow/Keras); AI harness = mock/chalsrv (no live
LLM; a real LLM needs an API key + tokens). Classify A (local, our image) / B (server or
live-LLM/API dependent) / C (not reproducible offline).

## Candidate sources

| source | kind | license | offline w/ our image | class | contamination |
|---|---|---|---|---|---|
| MadryLab `mnist_challenge`, `cifar10_challenge` | adversarial example (Linf eps), secret model + local `run_attack.py` | MIT | model downloads offline, BUT **TensorFlow (TF1-era, 2017)** — not our torch/onnx image | **A\*** (framework friction) | **VERY HIGH** (public since 2017, saturated leaderboards + PGD/transfer writeups) |
| alexdevassy `Machine_Learning_CTF_Challenges` — **Persuade** | model-file: malicious **PyTorch** model deserialization (pickle RCE) | not shown on page (verify LICENSE) | PyTorch + Flask, self-host, no external LLM | **A** | moderate (public repo + writeups likely) |
| same repo — **Vault** (model inversion), **Heist** (data poisoning CV) | model-inversion / poisoning, Flask + NN/CV | " | local, but framework unconfirmed (Keras vs torch?) | **A?** (verify framework) | moderate |
| same repo — **Fourtune** | model extraction + adversarial, `model.h5` | " | **Keras/HDF5** — not our image | **A\*** (framework) | moderate |
| same repo — **Dolos / Dolos II** | prompt injection → RCE / SQLi | " | needs an **OpenAI LLM backend** (API key) | **B** | moderate |
| same repo — **Matrix / Rogue / Mirage** | multi-agent / MCP trust / supply chain | " | need LLM backends (A2A/MCP) | **B** | moderate |
| ethz-spylab **SaTML 2024 LLM CTF** (`satml-llm-ctf` code + HF `ctf-satml24` dataset) | prompt injection (extract secret in system prompt) + defenses | repo/dataset public (verify) | platform queries hosted models (GPT-3.5 / Llama-2-70B) → needs a live LLM | **B** (dataset itself = offline reference data, not runnable challenges) | **HIGH** (full dataset + paper public) |
| **DEF CON AI Village CTF** (DEFCON30 "22 chals" / DEFCON31 "~27", Kaggle) | mixed ML-security (evasion, inversion, extraction, inject) | Kaggle comp terms | **servers offline**, Kaggle backend/data gone; only writeups remain | **C** (mostly) / B | **VERY HIGH** (Kaggle notebooks + GitHub solutions public) |
| **Gandalf (Lakera)**, **Dreadnode Crucible** | hosted prompt-injection / AI red-team | hosted service ToS | live hosted API only | **B/C** | high |
| **HackAPrompt** | prompt-injection **dataset** (not challenges) | public dataset | offline data, but no runnable solve target | **C** as a target (useful as an experience seed) | n/a |
| recent comps — **DiceCTF 2026**, **BSidesSF 2025** model-attack chals (seen only via 3rd-party skill indexes) | model-file (.pt/.safetensors, weight diff, LoRA) | per-comp (verify) | likely self-hostable; **unverified** | **A? (verify)** | **LOW** (recent) — most promising if real |

\* A\* = offline-reproducible in principle but NOT in our image (TF1/Keras); would need a
separate TF/Keras container.

## Reading of the landscape
- **Model-file A-local in our torch/onnx image is thin and framework-fragmented.** The one
  clean PyTorch model-file challenge found is alexdevassy **Persuade** (pickle-RCE on model
  upload) ± **Vault** (model inversion, framework to confirm). The canonical adversarial
  benchmarks (Madry MNIST/CIFAR) are TF1 + saturated/contaminated; others are Keras.
- **Prompt-injection / guard / agent challenges are almost all B** — they need a live LLM or
  external API (tokens). Our offline mock/chalsrv approach can't blind-measure a real model;
  a real AI-injection C0 needs an API-key budget (a separate cost decision), not just loading.
- **Contamination is HIGH on every well-known public set** (Madry, AI Village, SaTML) — same
  problem as our NYU pwn/misc sets: public writeups/leaderboards → measures headroom/ranking,
  not absolute skill. The only plausibly LOW-contamination targets are very recent (2025-2026)
  competition model-file challenges, which need DIRECT source verification (license, files,
  offline) and must NOT be sourced via the 3rd-party "ctf-ai-ml" skills — those were flagged
  CRITICAL/HIGH in public audits (embedded jailbreak payloads); we do not install/copy them.

## Recommendation (for the step-2 approval decision)
Do NOT over-invest. If step-2 is approved, the bounded, honest options are:
1. **mlsec A-local, our image**: verify LICENSE + framework of alexdevassy **Persuade** (PyTorch,
   model-file deserialization) and **Vault**; if MIT/BSD-like and torch, load 1–3 blind and run a
   first mlsec C0 (3-bucket, evidence-chain). Small N, moderate contamination — a sanity C0, not a
   skill claim.
2. **Recent low-contamination model-file chals** (DiceCTF2026 / BSidesSF2025) — only if their OWN
   public repos are found and verified (license + offline + our image). Higher value, more recon cost.
3. **Real AI-injection C0** (SaTML-style / Dolos) is a **B** path needing an API-key token budget —
   a separate explicit cost decision, out of scope for an offline baseline.

Net: sourcing exists but is thin/contaminated for our offline image; the clean next step is a
small PyTorch model-file C0 (option 1) pending license/framework verification — or stop if the
yield looks too low to justify.

## Phase 32-2 verification outcome (2026-10-31): STOP — no loadable candidate

Before any loading, verified the license + framework of the only clean offline candidate.
- **alexdevassy/Machine_Learning_CTF_Challenges — LICENSE: NONE declared.** GitHub license
  API returns null; no top-level LICENSE file (only README.md); README declares no license
  (only OWASP/MITRE mappings). Undeclared ⇒ all-rights-reserved by default ⇒ FAILS the
  "MIT/BSD-only, license-confirmed" gate. Not loaded/cloned/redistributed. (Note: the repo has
  also evolved — Persuade is now an LLM/agent "access the Vault" prompt-injection challenge, i.e.
  a **B** live-LLM path, not the earlier PyTorch-deserialization; Fourtune is Keras.)
- **MadryLab MNIST/CIFAR (MIT)** — fails the FRAMEWORK gate: TF1-era TensorFlow, not our
  torch/onnx `mlsec:0.1` image (out of scope for a PyTorch sanity C0).

**Result: no A-local, our-image, license-and-framework-clean model-file challenge is available
to load.** Honest stop — nothing loaded, no vault access, no code/test changes (suite still
251 green). The mlsec harness remains proven only on the synthetic set (Phase 28). Real-problem
mlsec C0 is blocked on sourcing, not on our harness.

Next options (await approval, do not start): (a) find a recent model-file CTF with its OWN
permissive-licensed public repo + PyTorch/ONNX + offline eval (more recon); (b) decide the
AI-injection resourcing path (a B/live-LLM API-token budget); or (c) fix the pwn deployment gap.
