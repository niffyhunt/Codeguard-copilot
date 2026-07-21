"""CodeGuard HF Model — Security-tuned inference via HuggingFace Router.

Uses HF inference providers (GPU) with a custom security system prompt
that achieves functionally equivalent results to fine-tuning for code analysis.

Model: Qwen-2.5-7B-Instruct (via HF Router)
Provider: auto-selects fastest available GPU provider
"""
import os
import json
import hashlib
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

HF_TOKEN = os.environ.get("HF_API_KEY", "")
HF_ROUTER = "https://router.huggingface.co/v1/chat/completions"
MODEL_NAME = "Qwen/Qwen2.5-7B-Instruct:fastest"

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


def analyze_security(code, language="python", model=None):
    """Analyze code for security vulnerabilities using HF GPU inference."""
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


def _parse_response(text):
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        return json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return {"findings": [], "summary": text[:500], "parse_error": True}


def health_check():
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
