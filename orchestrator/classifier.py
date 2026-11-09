"""Rule-based dummy classifier: file extensions + keywords -> category. No LLM."""
import os

# Order matters: it is the deterministic tie-breaker.
CATEGORIES = ("crypto", "pwn", "web", "rev", "forensics", "ai")

EXTENSION_RULES = {
    ".sage": "crypto", ".pem": "crypto",
    ".so": "pwn",
    ".php": "web", ".html": "web", ".js": "web",
    ".exe": "rev", ".elf": "rev", ".apk": "rev", ".wasm": "rev",
    ".pcap": "forensics", ".pcapng": "forensics", ".img": "forensics", ".raw": "forensics",
    # AI/ML model-file axis (mlsec sub-harness) routes to the ai lane.
    ".pt": "ai", ".pth": "ai", ".onnx": "ai", ".safetensors": "ai", ".ckpt": "ai",
}

KEYWORD_RULES = {
    "crypto": ("rsa", "aes", "cipher", "encrypt", "decrypt", "modulus", "lattice", "ecdsa", "prng"),
    "pwn": ("overflow", "heap", "rop", "shellcode", "libc", "format string", "uaf"),
    "web": ("http", "xss", "sqli", "cookie", "csrf", "ssrf", "flask", "express"),
    "rev": ("reverse", "crackme", "decompile", "obfuscat", "vm "),
    "forensics": ("pcap", "memory dump", "disk image", "steg"),
    # AI/LLM security (ACDC-style): prompt injection, guard bypass, RAG/agent attacks.
    "ai": ("prompt injection", "prompt-injection", "jailbreak", "guardrail",
           "guard bypass", "system prompt", "rag poisoning", "agent pipeline",
           "llm", "chatbot", "tool-calling agent",
           # model-file / adversarial-ML
           "adversarial", "fgsm", "pgd", "classifier model", "model weights",
           "onnx", "safetensors", "perturbation", "scoring server"),
}


def classify(challenge):
    """Return a category string for a challenge dict ({name, description, files})."""
    scores = {c: 0 for c in CATEGORIES}
    for path in challenge.get("files", []):
        cat = EXTENSION_RULES.get(os.path.splitext(path)[1].lower())
        if cat:
            scores[cat] += 2
    text = f"{challenge.get('name', '')} {challenge.get('description', '')}".lower()
    for cat, words in KEYWORD_RULES.items():
        scores[cat] += sum(1 for w in words if w in text)
    best = max(CATEGORIES, key=lambda c: (scores[c], -CATEGORIES.index(c)))
    return best if scores[best] > 0 else "misc"
