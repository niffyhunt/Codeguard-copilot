"""CodeGuard — AI Provider Architecture. Provider-agnostic, OpenAI-compatible first."""
import os
import json
import re
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


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

    def _request(self, endpoint, payload):
        url = f"{self.base_url}/chat/completions"
        data = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security code reviewer. Be concise. Respond in JSON."},
                {"role": "user", "content": payload}
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.1,
        }).encode()

        req = Request(url, data=data, headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        })

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read())
                return result.get("choices", [{}])[0].get("message", {}).get("content", "")
        except HTTPError as e:
            logger.error(f"AI provider HTTP {e.code}: {e.read()[:200]}")
        except URLError as e:
            logger.error(f"AI provider unreachable: {e.reason}")
        except Exception as e:
            logger.error(f"AI provider error: {e}")
        return ""

    def analyze(self, code, language, findings):
        if not self.api_key:
            return []

        existing = "\n".join([f"- {f.rule_id}: {f.message}" for f in findings[:10]])
        prompt = (
            f"Review this {language} code for security vulnerabilities beyond the already-detected patterns.\n\n"
            f"ALREADY DETECTED:\n{existing}\n\n"
            f"CODE TO REVIEW:\n```{language}\n{code[:3000]}\n```\n\n"
            f"Find logic flaws, auth bypasses, race conditions, framework misuse, or crypto weaknesses.\n"
            f"Return ONLY a JSON array: [{{\"type\":\"...\",\"severity\":\"critical|high|medium|low\","
            f"\"line\":1,\"message\":\"...\",\"explanation\":\"...\",\"fix\":\"...\"}}]"
        )

        response = self._request("/chat/completions", prompt)
        return self._parse_findings(response)

    def explain(self, finding, code_context=""):
        if not self.api_key:
            return finding.get("explanation", "")

        prompt = (
            f"Explain this security finding in detail:\n\n"
            f"Type: {finding.get('rule_id', 'Unknown')}\n"
            f"Severity: {finding.get('severity', 'medium')}\n"
            f"CWE: {finding.get('cwe', 'N/A')}\n"
            f"Message: {finding.get('message', '')}\n\n"
            f"CODE CONTEXT:\n```\n{code_context[:2000]}\n```\n\n"
            f"Explain: what the vulnerability is, how attackers exploit it, and how to fix it."
        )
        return self._request("/chat/completions", prompt)

    def health_check(self):
        if not self.api_key:
            return False
        try:
            result = self._request("/chat/completions", "Respond with only: ok")
            return "ok" in result.lower()
        except Exception:
            return False

    def _parse_findings(self, response):
        findings = []
        try:
            match = re.search(r"\[\s*\{[\s\S]*\}\s*\]", response)
            if match:
                items = json.loads(match.group())
                for item in items:
                    item["confidence"] = "ai-assigned"
                    item["source"] = "ai"
                    findings.append(item)
        except (json.JSONDecodeError, KeyError):
            pass
        return findings


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
    """Factory for AI providers. Supports: openai, anthropic, groq, or custom URL."""
    if provider_type in ("openai", "groq", "deepseek", "custom"):
        return OpenAICompatibleProvider(**kwargs)
    elif provider_type == "anthropic":
        return AnthropicProvider(**kwargs)
    return None
