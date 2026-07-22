"""CodeGuard Secret Detection v2 — entropy + structure + context.

Layer 2.5 scanning engine. Runs AFTER regex to:
1. Reduce false positives using entropy analysis
2. Detect structured secrets (JWT, AWS keys, SSH keys, etc.)
3. Verify context (assignment to secret-named variable, env config, etc.)
4. Score confidence (0.0–1.0)
"""
import re
import math
import os
from pathlib import Path


ENTROPY_THRESHOLD = 4.2  # bits per character — most secrets above this
MIN_SECRET_LENGTH = 8
MAX_SECRET_LENGTH = 2048


class SecretResult:
    def __init__(self, secret_type, value, line, column, length, entropy, confidence, context, file_path, fix):
        self.secret_type = secret_type
        self.value = value
        self.line = line
        self.column = column
        self.length = length
        self.entropy = entropy
        self.confidence = confidence
        self.context = context
        self.file_path = file_path
        self.fix = fix

    def to_dict(self):
        return {
            "rule_id": f"Secret: {self.secret_type}",
            "severity": "critical",
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "length": self.length,
            "message": f"{self.secret_type} detected with {self.confidence} confidence",
            "explanation": f"Found {self.secret_type.lower()} (entropy: {self.entropy:.1f} bits/char, context: {self.context}) in source code. Secrets in source are scraped by automated tools.",
            "fix": self.fix,
            "cwe": "CWE-798",
            "confidence": self.confidence,
            "analyzer": "secret-detection-v2",
        }


STRUCTURED_PATTERNS = [
    ("AWS Access Key", r"(?:AKIA|ASIA)[0-9A-Z]{16}", "aws"),
    ("AWS Secret Key", r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", "aws"),
    ("GitHub PAT", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "github"),
    ("GitLab PAT", r"glpat-[A-Za-z0-9_-]{20,}", "gitlab"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "slack"),
    ("Discord Bot Token", r"[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}", "discord"),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt"),
    ("SSH Private Key", r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "ssh"),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp"),
    ("Google Service Account", r"\w+@\w+\.iam\.gserviceaccount\.com", "google"),
    ("Heroku API Key", r"heroku[a-zA-Z0-9_-]{32,}", "heroku"),
    ("Stripe Live Key", r"sk_live_[0-9A-Za-z]{24,}", "stripe"),
    ("Stripe Test Key", r"sk_test_[0-9A-Za-z]{24,}", "stripe"),
    ("Stripe Publishable", r"pk_(?:live|test)_[0-9A-Za-z]{24,}", "stripe"),
    ("Twilio API Key", r"SK[0-9A-Fa-f]{32}", "twilio"),
    ("Twilio Auth Token", r"(?i)twilio[_-]?auth[_-]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{32})['\"]", "twilio"),
    ("Cloudflare API Key", r"(?i)cloudflare[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{37})['\"]", "cloudflare"),
    ("Docker Hub Token", r"dckr_pat_[A-Za-z0-9_-]{20,}", "docker"),
    ("NPM Token", r"npm_[A-Za-z0-9]{36}", "npm"),
    ("PyPI Token", r"pypi-[A-Za-z0-9]{20,}", "pypi"),
    ("Generic Base64 Secret", r"(?:[A-Za-z0-9+/]{40,}={0,2})", "generic"),
    ("Generic Hex Secret", r"(?:[0-9A-Fa-f]{32,})", "generic"),
]

CONTEXT_KEYWORDS = [
    "password", "secret", "token", "api_key", "apikey", "api_secret", "apisecret",
    "access_key", "accesskey", "private_key", "privatekey", "auth", "auth_token",
    "bearer", "jwt", "credential", "cred", "passwd", "pass", "pwd",
    "secret_key", "secretkey", "consumer_key", "consumer_secret",
    "client_secret", "client_id", "app_secret", "app_id",
    "connection_string", "connstr", "conn_string",
    "db_password", "db_user", "db_host",
]

CONTEXT_ASSIGNMENT_PATTERN = re.compile(
    r'(?:'
    + '|'.join(re.escape(kw) for kw in CONTEXT_KEYWORDS)
    + r')\s*[:=]\s*[\'"]',
    re.IGNORECASE,
)


def shannon_entropy(s):
    if not s:
        return 0.0
    s = s.strip("\"'`")
    length = len(s)
    if length < 3:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy


def is_high_entropy(s, threshold=ENTROPY_THRESHOLD):
    s = s.strip("\"'`")
    if len(s) < MIN_SECRET_LENGTH:
        return False
    if len(s) > MAX_SECRET_LENGTH:
        return False
    if s.isdigit():
        return False
    if s.isalpha() and s.isascii():
        return False
    return shannon_entropy(s) >= threshold


def detect_structure(value):
    value = value.strip("\"'`")
    for secret_type, pattern, _ in STRUCTURED_PATTERNS:
        if re.fullmatch(pattern, value):
            return secret_type
    return None


def score_context(context_line, context_before, context_after, var_name):
    score = 0.0
    combined = f"{context_line} {context_before} {context_after} {var_name}".lower()

    for kw in CONTEXT_KEYWORDS:
        if kw in combined:
            score += 0.15
        if kw == var_name.lower().strip():
            score += 0.25

    if re.search(r'(?:export|set|env)\s+\w+', combined):
        score += 0.2
    if re.search(r'os\.environ|os\.getenv|process\.env|env\b', combined):
        score += 0.15
    if re.search(r'(?:config|settings|conf)\b', combined):
        score += 0.1
    if re.search(r'\.env|credentials|\.secret|\.key|\.pem|\.pfx', combined):
        score += 0.15
    if re.search(r'[\'"]\s*\+\s*[\'"]|f[\'"]|\.format\(|%s|%d', combined):
        score -= 0.3
    if re.search(r'print|log|debug|trace|console\.log|puts\b', combined):
        score -= 0.2
    if re.search(r'(?:test|example|sample|dummy|placeholder|fake|mock)', combined):
        score -= 0.5

    return max(0.0, min(1.0, score))


def scan_file(file_path, code, output_format="finding"):
    findings = []
    if not file_path or not code:
        return findings

    is_test = any(indicator in file_path.lower() for indicator in
                  ["test", "spec", "fixture", "example", "mock", "__pycache__"])
    if is_test:
        return findings

    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        col = 0
        original_line = line

        cleaned_line = re.sub(r'[\'"]\s*\+\s*[\'"]', '', line)
        cleaned_line = re.sub(r'/\*.*?\*/', '', cleaned_line, flags=re.DOTALL)
        cleaned_line = re.sub(r'//.*$|#.*$', '', cleaned_line)

        for match in re.finditer(r'[\'"]([^\'"]{'
                                 + str(MIN_SECRET_LENGTH)
                                 + ','
                                 + str(MAX_SECRET_LENGTH)
                                 + r'})[\'"]', cleaned_line):
            value = match.group(1)
            col = match.start() + 1

            structured_type = detect_structure(value)
            entropy = shannon_entropy(value)
            high_entropy = entropy >= ENTROPY_THRESHOLD

            if not structured_type and not high_entropy:
                continue

            context_before = lines[i - 2] if i >= 2 else ""
            context_after = lines[i] if i < len(lines) else ""
            var_name = ""
            var_match = re.match(r'\s*(?:\w+\.)*(\w+)\s*=|(\w+)\s*:', line)
            if var_match:
                var_name = var_match.group(1) or var_match.group(2) or ""
            context_score = score_context(line, context_before, context_after, var_name)

            if structured_type:
                confidence = "high"
                fix = structured_type
            elif context_score >= 0.6:
                confidence = "high"
                fix = "environment variable"
            elif context_score >= 0.3:
                confidence = "medium"
                fix = "environment variable"
            else:
                confidence = "low"
                fix = "environment variable"

            secret_type = structured_type or "High-Entropy Secret"
            length = len(value)
            if length > 30:
                value_safe = value[:12] + "..." + value[-8:]
            else:
                value_safe = value[:8] + "..."

            if output_format == "finding":
                from .engine import Finding
                findings.append(Finding(
                    rule_id=f"Secret: {secret_type}",
                    severity="critical",
                    file_path=file_path,
                    line=i, column=col, length=len(value),
                    message=f"{secret_type} detected with {confidence} confidence",
                    explanation=f"Found {secret_type.lower()} (entropy: {entropy:.1f} bits/char, context: {context_score:.1f}) in source. Secrets in source code are automatically harvested by credential-scraping tools.",
                    fix=f"Store in {fix}. Never commit secrets to version control. Use .env files with .gitignore or a secrets manager.",
                    cwe="CWE-798",
                    confidence=confidence,
                    analyzer="secret-detection-v2",
                ))
            else:
                findings.append(SecretResult(
                    secret_type=secret_type,
                    value=value_safe,
                    line=i, column=col, length=len(value),
                    entropy=entropy,
                    confidence=confidence,
                    context=f"context_score={context_score:.1f}",
                    file_path=file_path,
                    fix=f"Store in {fix}",
                ).to_dict())

    return findings
