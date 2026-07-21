"""CodeGuard HF Model — Security-tuned inference via HuggingFace Router or local LoRA.

Mode 1 (default): HF Router API — uses HF inference providers (GPU) with a custom
security system prompt for code analysis.

Mode 2 (local): Loads the fine-tuned CodeGuard LoRA adapter directly from HuggingFace
using QLoRA 4-bit quantization. Enable with CODEGUARD_LOCAL_MODEL=1.

Fine-tuned model: Ezmcyber890/codeguard-security-7b (LoRA adapter on Qwen2.5-7B)
"""
import os
import json
import hashlib
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

HF_TOKEN = os.environ.get("HF_API_KEY", "")
HF_ROUTER = "https://router.huggingface.co/v1/chat/completions"
MODEL_NAME = "Qwen/Qwen2.5-7B-Instruct:fastest"
FINETUNED_REPO = "Ezmcyber890/codeguard-security-7b"
BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"

SECURITY_TUNING_PROMPT = """You are CodeGuard Security Analyzer — a fine-tuned model specialized in detecting security vulnerabilities in source code.

CAPABILITIES:
- Detect SQL injection, XSS, Command Injection, Hardcoded Secrets, Path Traversal, Insecure Deserialization
- Map findings to CWE identifiers
- Provide confidence scores (0.0-1.0)
- Suggest concrete fixes with code examples

RULES:
1. Only report vulnerabilities you can identify with evidence from the code
2. Never invent vulnerabilities that don't exist
3. Provide CWE IDs when applicable
4. Include confidence score for each finding
5. For each vulnerability, provide: type, severity, line number (if visible), explanation, fix
6. If code looks safe, say so explicitly
7. Format ALL responses as valid JSON

OUTPUT FORMAT:
{
  "findings": [
    {
      "type": "vulnerability type",
      "severity": "critical|high|medium|low",
      "cwe": "CWE-XXX",
      "line": line_number_or_null,
      "confidence": 0.0-1.0,
      "explanation": "why this is dangerous",
      "fix": "how to fix it with code example"
    }
  ],
  "summary": "brief overall assessment"
}"""

_cache = {}

# Lazy-loaded local model globals
_local_model = None
_local_tokenizer = None


def is_local_mode():
    return os.environ.get("CODEGUARD_LOCAL_MODEL", "").lower() in ("1", "true", "yes")


def has_gpu():
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False


def analyze_security(code, language="python", model=None):
    """Analyze code for security vulnerabilities.
    
    Uses local LoRA adapter if CODEGUARD_LOCAL_MODEL=1 and a GPU is available.
    Falls back to HF Router API otherwise.
    """
    if is_local_mode() and has_gpu():
        return _analyze_local(code, language)

    return _analyze_router(code, language, model)


def _analyze_router(code, language="python", model=None):
    """HF Router API inference (original behavior)."""
    if not HF_TOKEN:
        return {"error": "HF_API_KEY not set", "findings": []}

    model = model or MODEL_NAME
    cache_key = hashlib.sha256(f"{code[:500]}{model}".encode()).hexdigest()[:16]

    if cache_key in _cache:
        return _cache[cache_key]

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SECURITY_TUNING_PROMPT},
            {"role": "user", "content": f"Analyze this {language} code for security vulnerabilities:\n\n```{language}\n{code[:2500]}\n```"}
        ],
        "max_tokens": 500,
        "temperature": 0.1,
    }).encode()

    req = Request(HF_ROUTER, data=payload, headers={
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type": "application/json",
    })

    try:
        with urlopen(req, timeout=45) as resp:
            result = json.loads(resp.read())
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            parsed = _parse_response(content)
            if len(_cache) > 32:
                _cache.pop(next(iter(_cache)))
            _cache[cache_key] = parsed
            return parsed
    except Exception as e:
        return {"error": str(e)[:100], "findings": []}


def _analyze_local(code, language="python"):
    """Local inference using fine-tuned LoRA adapter with QLoRA 4-bit."""
    global _local_model, _local_tokenizer

    if _local_model is None:
        _load_local_model()

    if _local_model is None:
        return {"error": "Local model failed to load", "findings": []}

    prompt = (
        f"<|im_start|>user\nAnalyze for security:\n{code[:2000]}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )
    try:
        import torch
        inputs = _local_tokenizer(prompt, return_tensors="pt").to("cuda")
        with torch.no_grad():
            out = _local_model.generate(
                **inputs, max_new_tokens=200, temperature=0.1,
                pad_token_id=_local_tokenizer.eos_token_id,
            )
        response = _local_tokenizer.decode(out[0], skip_special_tokens=True)
        result = response.split("assistant\n")[-1].strip() if "assistant\n" in response else response
        return _parse_security_output(result)
    except Exception as e:
        return {"error": str(e)[:100], "findings": []}


def _load_local_model():
    """Load fine-tuned LoRA model with 4-bit quantization on GPU."""
    global _local_model, _local_tokenizer
    try:
        import gc
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel

        gc.collect()
        torch.cuda.empty_cache()

        _local_tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
        _local_tokenizer.pad_token = _local_tokenizer.eos_token

        base = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
            ),
            device_map="cuda:0", trust_remote_code=True,
        )
        _local_model = PeftModel.from_pretrained(base, FINETUNED_REPO)
        _local_model.gradient_checkpointing_disable()
        _local_model.eval()
        logger.info(f"Loaded fine-tuned model from {FINETUNED_REPO}")
    except Exception as e:
        logger.error(f"Failed to load local model: {e}")
        _local_model = None
        _local_tokenizer = None


def _parse_security_output(text):
    """Parse the local model's output into structured findings."""
    findings = []
    text_lower = text.lower()
    if "vulnerable" in text_lower or "cwe-" in text_lower:
        severity = "high"
        for word in ["critical", "high", "medium", "low"]:
            if word in text_lower:
                severity = word
                break
        cwe_match = __import__("re").search(r"CWE-\d+", text)
        findings.append({
            "type": text.split(":")[0].replace("VULNERABLE", "").strip() if ":" in text else "Unknown",
            "severity": severity,
            "cwe": cwe_match.group() if cwe_match else None,
            "line": None,
            "confidence": 0.9 if "vulnerable" in text_lower else 0.5,
            "explanation": text[:300],
            "fix": "",
        })
    return {"findings": findings, "summary": text[:200], "model": FINETUNED_REPO}


def _parse_response(text):
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        return json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return {"findings": [], "summary": text[:500], "parse_error": True}


def health_check():
    if is_local_mode() and has_gpu():
        return {"status": "local_model", "repo": FINETUNED_REPO, "gpu": True}
    if not HF_TOKEN:
        return {"status": "no_token"}
    payload = json.dumps({
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": "ok"}],
        "max_tokens": 5,
    }).encode()
    req = Request(HF_ROUTER, data=payload, headers={
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req, timeout=15) as resp:
            return {"status": "healthy", "model": MODEL_NAME}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)[:100]}
