"""CodeGuard — AI Provider Architecture. Provider-agnostic, OpenAI-compatible first.

Upgraded: structured security prompts, finding-aware analysis,
grounded output, simple LRU caching, confidence scoring.
"""
import os
import json
import re
import hashlib
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

_AI_CACHE = {}
_CACHE_MAX_SIZE = 64

SECURITY_SYSTEM_PROMPT = """You are a security code reviewer for CodeGuard Copilot.
Your job is to analyze specific security findings and provide grounded, evidence-backed explanations.

RULES:
1. Only analyze the finding provided. Do not invent new vulnerabilities.
2. Reference the finding's rule ID, CWE, and code location in your response.
3. If you cannot determine exploitability, say \"Insufficient context to determine.\"
4. Provide concrete remediation steps specific to the code shown.
5. Include a confidence score (0.0-1.0) for your analysis.
6. Never suggest executing attacker commands or payloads.
7. Format output as structured JSON only."""



class AIProvider:
    """Base provider interface."""

    def analyze(self, code: str, language: str, findings: list) -> list:
        raise NotImplementedError

    def explain(self, finding: dict, code_context: str) -> str:
        raise NotImplementedError

    def health_check(self) -> bool:
        raise NotImplementedError


class OpenAICompatibleProvider(AIProvider):
    """Works with OpenAI, Groq, DeepSeek, local LLMs — anything OpenAI-compatible."""

    def __init__(self, base_url=None, api_key=None, model=None, timeout=30, max_tokens=2000):
        self.base_url = (base_url or os.getenv("CODEGUARD_AI_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("CODEGUARD_AI_KEY", os.getenv("OPENAI_API_KEY", ""))
        self.model = model or os.getenv("CODEGUARD_AI_MODEL", "gpt-4o-mini")
        self.timeout = timeout
        self.max_tokens = max_tokens

    def _call_api(self, payload, cache_key=None):
        if cache_key and cache_key in _AI_CACHE:
            return _AI_CACHE[cache_key]
        url = f"{self.base_url}/chat/completions"
        data = json.dumps({
            "model": self.model, "max_tokens": self.max_tokens, "temperature": 0.1,
            "messages": [{"role": "system", "content": SECURITY_SYSTEM_PROMPT},
                         {"role": "user", "content": payload}],
        }).encode()
        req = Request(url, data=data, headers={
            "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json",
        })
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                content = json.loads(resp.read()).get("choices", [{}])[0].get("message", {}).get("content", "")
                if cache_key:
                    if len(_AI_CACHE) >= _CACHE_MAX_SIZE:
                        _AI_CACHE.pop(next(iter(_AI_CACHE)))
                    _AI_CACHE[cache_key] = content
                return content
        except HTTPError as e:
            logger.error(f"AI HTTP {e.code}: {e.read()[:200]}")
        except URLError as e:
            logger.error(f"AI unreachable: {e.reason}")
        except Exception as e:
            logger.error(f"AI error: {e}")
        return ""

    def analyze_finding(self, finding_dict, code_snippet=""):
        if not self.api_key:
            return {"error": "no_api_key"}
        rid = finding_dict.get("rule_id", "")
        fpath = finding_dict.get("file_path", "")
        fline = finding_dict.get("line", "")
        ck = hashlib.sha256(f"{rid}{fpath}{fline}".encode()).hexdigest()[:12]
        cache_key = f"af_{ck}"
        prompt = (
            "Analyze this specific security finding:\n"
            f"Rule: {rid}\n"
            f"Severity: {finding_dict.get('severity', 'medium')}\n"
            f"CWE: {finding_dict.get('cwe', 'N/A')}\n"
            f"File: {fpath}:{fline}\n"
            f"Source: {finding_dict.get('source', '')}\n"
            f"Sink: {finding_dict.get('sink', '')}\n"
            f"Analyzer: {finding_dict.get('analyzer', 'regex')}\n\n"
            f"CODE:\n```\n{code_snippet[:1500]}\n```\n\n"
            'Return ONLY JSON: {"exploitability":"high|medium|low|unknown",'
            '"confidence":0.0-1.0,'
            '"attack_scenario":"brief scenario",'
            '"remediation_steps":["step1"],'
            '"references":["CWE-XXX"]}'
        )
        response = self._call_api(prompt, cache_key=cache_key)
        try:
            m = re.search(r"\{[\s\S]*\}", response)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        return {"error": "parse_failed", "raw": response[:300]}

    def analyze(self, code, language, findings):
        return []

    def explain(self, finding, code_context=""):
        if not self.api_key:
            return finding.get("explanation", "")
        result = self.analyze_finding(finding, code_context)
        if "error" not in result:
            return "\n".join([
                f"Exploitability: {result.get('exploitability','?')} (confidence: {result.get('confidence','?')})",
                f"Attack scenario: {result.get('attack_scenario','?')}",
                f"Remediation: {'; '.join(result.get('remediation_steps',[]))}",
            ])
        return finding.get("explanation", "")

    def health_check(self):
        if not self.api_key:
            return False
        try:
            return "ok" in self._call_api("Respond with only: ok").lower()
        except Exception:
            return False


class AnthropicProvider(AIProvider):
    """Claude API via Anthropic."""

    def __init__(self, api_key=None, model="claude-sonnet-4-20250514", timeout=30):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = model
        self.timeout = timeout

    def _request(self, prompt):
        if not self.api_key:
            return ""
        data = json.dumps({
            "model": self.model,
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        req = Request("https://api.anthropic.com/v1/messages", data=data, headers={
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        })

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read())
                return result.get("content", [{}])[0].get("text", "")
        except Exception as e:
            logger.error(f"Anthropic error: {e}")
        return ""

    def analyze(self, code, language, findings):
        return []

    def explain(self, finding, code_context=""):
        if not self.api_key:
            return finding.get("explanation", "")
        prompt = f"Explain this security finding: {finding.get('message')}. Code: {code_context[:1500]}"
        return self._request(prompt)

    def health_check(self):
        return bool(self.api_key and self._request("Respond with only: ok"))


def create_provider(provider_type="openai", **kwargs):
    """Factory for AI providers. Supports: openai, anthropic, groq, deepseek, or custom URL."""
    if provider_type in ("openai", "groq", "deepseek", "custom"):
        return OpenAICompatibleProvider(**kwargs)
    elif provider_type == "anthropic":
        return AnthropicProvider(**kwargs)
    return None
