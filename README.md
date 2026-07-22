# CodeGuard Copilot — v0.5.0

[![PyPI version](https://img.shields.io/pypi/v/raven-guard?color=blue)](https://pypi.org/project/raven-guard/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

Security analysis engine — catches vulnerabilities before they ship. CLI, CI/CD, VS Code extension, or Python API. 64 patterns, 14 languages, 7 AST analyzers, optional fine-tuned model. Zero API calls required.

```
pip install raven-guard
codeguard scan .
```

## What It Detects

| Category | Examples |
|----------|----------|
| SQL Injection | Parameterized query violations, string concatenation, raw queries |
| Command Injection | Shell exec, subprocess, Runtime.exec, eval() |
| Hardcoded Secrets | Passwords, API keys, tokens, JWTs, SSH keys |
| Supply Chain | CVE deps, typosquatting, dependency confusion |
| IaC | Docker root, K8s privileged, S3 public, security groups |
| API | GraphQL introspection, gRPC no TLS, WebSocket origin |
| Memory Safety | Buffer overflow, UAF, format string, integer overflow |
| Mobile | WebView JS, cleartext, SQLite injection, implicit intents |
| Business Logic | IDOR, mass assignment, TOCTOU, data exposure |

**64 regex patterns total** across all categories. 14 languages: Python, JavaScript, TypeScript, Java, PHP, Go, Rust, C++, C, C#, Ruby, Kotlin, Swift, XML.

## Architecture

```
Source Code
    |
    v
+-- Layer 1: Regex (64 patterns, 14 languages) -+
|  SQLi . CMDi . XSS . Secrets . Supply Chain   |
|  IaC . API . Memory . Mobile . Business Logic |
+------------------------+----------------------+
                         |
                         v
+-- Layer 2: AST Analysis (tree-sitter, 7 langs) +
|  Python/JS/TS/Go/Rust/Java/PHP/Ruby/C#/Kotlin  |
|  Source->Sink dataflow . Scope taint tracking  |
+------------------------+----------------------+
                         |
                         v
+-- Layer 2.5: Secret Detection v2 --------------+
|  Entropy > 4.2 bits/char . 20+ structure types |
|  Context scoring (variable names, file type)   |
+------------------------+----------------------+
                         |
                         v
+-- Layer 3: WraithCore Model (optional, T4) ----+
|  Honeypot correlation . CVE exploit check      |
|  Phishing verification . Severity boosting     |
+------------------------+----------------------+
                         |
                         v
+-- Layer 4: Exploitability Scoring -------------+
|  0-10 score . Attack vector . Auth complexity  |
|  Public exploit POC detection                  |
+------------------------+----------------------+
                         |
                         v
           Findings + Reports
         SARIF . JSON . HTML . Markdown
```

## CLI

```bash
# Scan
codeguard scan .
codeguard scan app.py

# Environment-aware gating
codeguard scan . --env prod       # critical only
codeguard scan . --env staging    # high+
codeguard scan . --env dev        # all

# Export
codeguard scan . --format sarif --output results.sarif
codeguard scan . --format html --output report.html
codeguard scan . --format json
codeguard scan . --format markdown

# Advanced
codeguard scan . --exploitability -x   # 0-10 scoring
codeguard scan . --drift                # regression detection
codeguard scan . --plugin my_rules.py   # custom analyzer
codeguard scan . --fail-on high         # CI gate

# Health
codeguard doctor
```

## WraithCore Security Model (Optional)

Fine-tuned Qwen2.5-7B (LoRA adapter, 4-bit QLoRA) for:

- **Attacker Classification** — scanner, brute_forcer, interactive_attacker, ransomware_dropper, script_based
- **Phishing Detection** — credential_harvest, financial_fraud, prize_scam, delivery_fraud, account_takeover
- **CVE Scoring** — exploited_in_wild, difficulty (1-10), attack_vector, KEV status

**Training dataset:** 1,666 examples from WraithWall honeypot network (500 sessions), OpenPhish + URLhaus (500 URLs), CISA KEV (500 CVEs), and benign samples (166). Trained on T4 GPU via QLoRA.

```bash
# Requires GPU
pip install raven-guard[wraithcore]
codeguard scan .
```

Or use any OpenAI-compatible model:
```bash
export CODEGUARD_AI_KEY=sk-...
codeguard scan .
```

## Secret Detection v2

Entropy-based detection finds secrets that regex misses. 20+ structured types with context scoring:

- AWS keys (AKIA/ASIA + 16 chars)
- GitHub PATs (ghp_/gho_/ghu_/ghs_/ghr_ + 36 chars)
- JWT tokens (eyJ...base64url.base64url)
- SSH/PGP keys (-----BEGIN...PRIVATE KEY-----)
- Stripe, Twilio, Cloudflare API keys
- High-entropy strings (Shannon > 4.2 bits/char)

## Exploitability Scoring

Every finding scored 0-10 based on attack vector, authentication requirements, complexity, and discoverability. Known public exploit POCs auto-boost the score.

## Raven Intelligence (WraithWall)

When connected to WraithWall, findings cross-reference against live Cowrie honeypot attacker sessions. If a CWE-89 finding matches SQL injection commands real attackers are using right now, priority gets elevated.

```bash
export RAVEN_API_KEY=your_key
export RAVEN_API_URL=https://wraithwall.online/api/raven
codeguard scan .
```

## API Server

```bash
uvicorn codeguard.wraithcore_api:app --host 0.0.0.0 --port 8765

curl -X POST http://localhost:8765/wraithcore/classify-attacker \
  -H "Content-Type: application/json" \
  -d '{"src_ip":"49.7.233.99","commands":[],"downloads":[]}'
```

## Custom Rules

Create `.codeguard.json` in project root:

```json
{
  "customPatterns": [{
    "type": "Custom: Banned Function",
    "severity": "critical",
    "regex": "eval\\s*\\(.*userInput",
    "languages": ["javascript", "python"],
    "message": "eval() with user input is dangerous",
    "fix": "Use a parser instead of eval()",
    "cwe": "CWE-95"
  }]
}
```

## Python API

```python
from codeguard import CodeGuardEngine

engine = CodeGuardEngine()
findings = engine.scan_file("app.py")
for f in findings:
    print(f"{f.severity}: {f.rule_id} at line {f.line}")
```

## CI/CD

```yaml
# GitHub Actions
- name: CodeGuard Scan
  run: |
    pip install raven-guard
    codeguard scan . --fail-on high --format sarif --output results.sarif
```

## Installation

```bash
pip install raven-guard
pip install raven-guard[wraithcore]   # with model support
```

## License

MIT — see LICENSE file.
