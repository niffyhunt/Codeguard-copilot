# CodeGuard Copilot — Intelligent Security Ecosystem

<div align="center">

![Version](https://img.shields.io/badge/version-0.5.0-purple.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Patterns](https://img.shields.io/badge/patterns-64-blue.svg)
![Languages](https://img.shields.io/badge/languages-14-orange.svg)
![WraithCore](https://img.shields.io/badge/WraithCore-Qwen2.5--7B-purple.svg)

**Your AI-Powered Security Guardian — Now Connected to Live Attacker Intelligence**

[Features](#-features) • [Architecture](#-architecture) • [Raven Integration](#-raven-intelligence-bridge) • [Installation](#-installation) • [Roadmap](#-implementation-status) • [Contributing](#-contributing)

</div>

---

## What is CodeGuard Copilot?

CodeGuard Copilot catches security vulnerabilities **as you code**, not after you commit. It combines deterministic regex pattern detection with AI-powered deep analysis and live attacker intelligence from the Raven/WraithWall ecosystem to give you context no other VS Code security extension can.

**What makes it different:**
- **50+ vulnerability patterns** across JavaScript, TypeScript, Python, Java, PHP, Go, Rust, C++, C#, Ruby
- **Raven Intelligence Bridge** — attacker behavior from live honeypots informs which vulnerabilities matter most
- **Security Knowledge Graph** — connects findings to CWEs, MITRE techniques, attacker behavior, and remediation
- **AI Security Rule Generation** — learns new detection patterns from real-world exploit data
- **Interactive Security Training** — learn WHY code is vulnerable, not just THAT it is

---

## Features

### Real-Time Detection (Phase 1)

- Scans as you type with configurable debounce (default 500ms)
- 35+ built-in vulnerability patterns (17 core + 18 expanded)
- Multi-language: JS, TS, Python, Java, PHP, Go, Rust, C++, C#, Ruby
- Pattern-based detection (<10ms response)
- Workspace-wide scanning with progress tracking

### AI-Powered Deep Analysis (Phase 1)

- Context-aware security analysis using Claude, GPT-4, or Groq
- Identifies logic flaws, business logic vulnerabilities, and framework anti-patterns
- Configurable AI provider and API key
- Daily usage budget (guard against API costs)

### Custom Rules & Plugins (Phase D)

- `.codeguard.json` custom rule configuration — regex, severity, CWE, per-file
- Plugin system for custom analyzers (SecurityAnalyzer interface)
- Shared rule sets for team collaboration
- Rule suppressions and path exclusions

### Raven Intelligence Bridge (Phase D)

- **Attacker → Pattern**: Cowrie honeypot attacker behavior → proposed CodeGuard patterns
- **Code → Threat**: CodeGuard findings → MITRE-mapped threat feedback for Raven
- **Attacker-Aligned Prioritization**: Findings that match real attacker behavior get elevated priority
- **Security Knowledge Graph**: finding → file → function → CWE → MITRE → attacker behavior → fix

### Security Training Mode (Phase D)

- 3 interactive training modules (SQLi, XSS, hardcoded secrets)
- Vulnerable vs secure code side-by-side
- Real-world breach examples + quiz
- Webview-based — works inside VS Code

### CI/CD Native Integration

- GitHub Actions workflow (scan on push/PR, Semgrep + Snyk bridge)
- GitLab CI example configuration
- Artifact upload for security reports

### Intelligent Quick Fixes

- One-click secure code replacements
- "Explain this vulnerability" → webview with detailed analysis
- "Learn more" → opens CWE reference
- "Ignore this warning" → inline suppression comments

---

## Architecture

```
Developer Code
    │
    ▼
┌──────────────────────────────────────────────┐
│           CodeGuard Copilot                   │
│                                               │
│  ┌──────────────┐  ┌──────────────┐          │
│  │  Pattern     │  │  AST / AI     │          │
│  │  Detection   │  │  Analysis     │          │
│  │  (regex)     │  │  (Claude/GPT) │          │
│  │  35+ rules   │  │               │          │
│  └──────┬───────┘  └──────┬────────┘          │
│         │                 │                    │
│         ▼                 ▼                    │
│  ┌──────────────────────────────────────┐     │
│  │        Vulnerability Findings         │     │
│  │  severity · CWE · file · confidence   │     │
│  └──────────────────┬───────────────────┘     │
│                     │                          │
│                     ▼                          │
│  ┌──────────────────────────────────────┐     │
│  │       Intelligence Pipeline           │     │
│  │                                       │     │
│  │  ┌─────────────┐  ┌────────────────┐  │     │
│  │  │ Knowledge    │  │ Raven Bridge    │  │     │
│  │  │ Graph        │  │ ← attacker data │  │     │
│  │  │ finding→CWE  │  │ → threat intel  │  │     │
│  │  │ →MITRE→fix   │  │                 │  │     │
│  │  └─────────────┘  └────────────────┘  │     │
│  └──────────────────┬───────────────────┘     │
│                     │                          │
│                     ▼                          │
│  ┌──────────────────────────────────────┐     │
│  │         Developer Feedback            │     │
│  │  QuickFix · Explain · Suppress · Fix  │     │
│  │  Training · Report · CI/CD            │     │
│  └──────────────────────────────────────┘     │
│                                               │
└──────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│              WraithWall / Raven               │
│                                               │
│  Cowrie Honeypot → Attacker Telemetry         │
│  Campaign Correlation → Behavioral DNA        │
│  CISA KEV → OWASP → Composite Scoring         │
│  Cross-Repo Systemic Patterns                 │
│  Dark-Web Breach Monitoring                   │
└──────────────────────────────────────────────┘
```

---

## Raven Intelligence Bridge

CodeGuard Copilot is the **frontend intelligence consumer** for Raven's attacker telemetry pipeline. When Cowrie honeypots observe real attackers using exploitation techniques, the patterns flow into CodeGuard:

```
Attacker uses SQL injection on honeypot
    ↓
Raven detects: CWE-89, credential_access, threat_score=85
    ↓
RavenIntelBridge.ingestEvent() receives event
    ↓
Generates candidate CodeGuard pattern at confidence 0.85
    ↓
Proposed pattern: "SQL Injection (attacker-observed)"
    ↓
Human review → published as CodeGuard rule
    ↓
Developers protected against the actual exploit
```

Conversely, when CodeGuard finds a vulnerability, it generates structured Raven feedback:

```
CodeGuard finding: CWE-798 hardcoded secret in auth/login.js
    ↓
RavenThreatFeedback.generateIntelligence()
    ↓
MITRE techniques: T1552, T1078
    ↓
Raven priority score: 72 (network attack vector, low complexity)
    ↓
Raven elevates this finding in composite scoring
    ↓
SOC team sees: "Attacker-aligned credential finding in production repo"
```

---

## Detected Vulnerability Categories

### Critical
SQL Injection (CWE-89), Command Injection (CWE-78), NoSQL Injection (CWE-943), Hardcoded Secrets (CWE-798), Insecure Deserialization (CWE-502)

### High
XSS (CWE-79), DOM-based XSS, Path Traversal (CWE-22), File Upload (CWE-434), Weak Crypto (CWE-327), Unsafe Blocks (Rust), Unescaped HTML (Go)

### Medium
CORS Misconfiguration (CWE-942), Open Redirect (CWE-601), Insecure Random (CWE-338), ReDoS (CWE-1333), Memory Leak (C++), Mass Assignment (Ruby)

### Low
Weak Password Storage, Express Trust Proxy, Missing Security Headers, Framework anti-patterns

### Language-specific (18 new)
Go: SQLi, Insecure Random, Hardcoded Secret, Unescaped HTML
Rust: Unsafe Block, Hardcoded Secret, Command Injection, Weak Crypto
C++: Buffer Overflow, Memory Leak, SQL Injection
C#: SQL Injection, Connection String, Insecure Deserialization
Ruby: SQL Injection, Command Injection, Mass Assignment, Unsafe YAML

---

## Fine-Tuned Security Model (v0.3.1)

CodeGuard's fine-tuned model (`Ezmcyber890/codeguard-security-7b`) is a LoRA adapter on **Qwen2.5-7B-Instruct** trained on 32 security vulnerability patterns across 8 categories:

- **Mode 1 (default — HF Router API):** No GPU needed. Uses HuggingFace's fastest inference provider with a custom security system prompt.
- **Mode 2 (local GPU — `CODEGUARD_LOCAL_MODEL=1`):** Loads the fine-tuned LoRA adapter with QLoRA 4-bit quantization. Requires ~5GB GPU VRAM.

```bash
# Local GPU inference
CODEGUARD_LOCAL_MODEL=1 codeguard scan app.py

# Or via Python
CODEGUARD_LOCAL_MODEL=1 python3 -c "
from codeguard import CodeGuardEngine
engine = CodeGuardEngine(use_local_model=True)
findings = engine.scan_file('app.py')
print(findings)
"
```

**Training dataset:** 1,666 examples from WraithWall honeypot network (500 sessions), OpenPhish + URLhaus (500 phishing URLs), CISA KEV (500 CVEs), and benign samples (166). Trained on T4 GPU via QLoRA.

---

## Installation

```bash
git clone https://github.com/niffyhunt/codeguard-copilot.git
cd codeguard-copilot
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

### Python CLI (PyPI: raven-guard)

```bash
pip install raven-guard
raven-guard scan .
raven-guard scan app.py --severity critical,high
raven-guard scan . --format sarif --output results.sarif
raven-guard doctor
```

### Configuration

```json
{
  "codeguard.enableRealtime": true,
  "codeguard.scanDelay": 500,
  "codeguard.aiProvider": "groq",
  "codeguard.enableAI": true,
  "codeguard.enablePlugins": true,
  "codeguard.enableTraining": true,
  "codeguard.severityFilter": ["critical", "high", "medium"]
}
```

### Custom Rules (.codeguard.json)

```json
{
  "version": "0.1.0",
  "customPatterns": [{
    "id": "my-custom-rule",
    "type": "Custom: Unsafe Function",
    "severity": "high",
    "regex": "eval\\\\(.*userInput",
    "languages": ["javascript"],
    "message": "eval() with user input detected",
    "cwe": "CWE-95"
  }],
  "severityOverrides": { "SQL Injection": "critical" },
  "excludedPaths": ["vendor/", "node_modules/", "*.test.ts"]
}
```

---

## Implementation Status

| Feature | Status |
|---------|--------|
| 64 vulnerability patterns across 14 languages | **v0.5.0** |
| 7 tree-sitter AST analyzers (Python/JS/TS/Go/Rust/Java/PHP/Ruby/C#/Kotlin) | **v0.5.0** |
| Secret detection v2 (entropy + 20+ structured types) | **v0.5.0** |
| Exploitability scoring (0-10 with attack vector) | **v0.5.0** |
| WraithCore-7B fine-tuned model (attacker/phishing/CVE) | **v0.5.0** |
| WraithCore API server (FastAPI) | **v0.5.0** |
| Multi-environment gating (--env prod/staging/dev) | **v0.5.0** |
| Security drift detection (--drift) | **v0.5.0** |
| Plugin system (--plugin custom analyzers) | **v0.5.0** |
| HTML/Markdown report export | **v0.5.0** |
| CLI: SARIF/JSON/HTML/Markdown export | **v0.5.0** |
| Cross-repo systemic detection (threshold ≥2) | **v0.5.0** |
| Raven honeypot intelligence bridge | **v0.5.0** |
| .codeguard.json custom rules | **v0.5.0** |
| CI/CD GitHub Actions + GitLab | **v0.5.0** |
| Pre-commit hook support | **v0.5.0** |
| VS Code extension with QuickFix | **v0.4.0** |
| Real-time scanning (regex patterns) | Prod |
| PyPI package: raven-guard | v0.3.2 |
| VS Code Marketplace publication | Planned |
| Telemetry dashboard | Research |

---

## Repository Structure

```
codeguard-copilot/
├── .codeguard.example.json     # Custom rules template
├── .github/workflows/ci.yml    # GitHub Actions CI/CD
├── .gitlab-ci.example.yml      # GitLab CI integration
├── package.json                # Extension manifest (0.2.0)
├── tsconfig.json               # TypeScript config
├── README.md                   # This file
├── SETUP_GUIDE.md              # Detailed setup
└── src/
    ├── extension.ts            # Entry point, VS Code lifecycle
    ├── patterns/
    │   ├── vulnerabilityPatterns.ts   # 17 base patterns
    │   ├── expandedPatterns.ts        # 18 language-specific patterns
    │   └── securityScanner.ts         # Two-phase scanner
    ├── ai/
    │   └── aiEngine.ts         # Claude/GPT/Groq integration
    ├── Ui/
    │   ├── diagnostics.ts       # VS Code diagnostic rendering
    │   └── quickFix.ts          # Quick fixes + explain webview
    ├── config/
    │   └── customRules.ts       # .codeguard.json loader
    ├── plugins/
    │   └── registry.ts          # Plugin system framework
    ├── raven/
    │   ├── bridge.ts            # Raven → CodeGuard intelligence
    │   └── feedback.ts          # CodeGuard → Raven threat feedback
    ├── knowledge/
    │   └── graph.ts             # Security finding knowledge graph
    ├── training/
    │   └── mode.ts              # Interactive security training
    └── jetbrains/
        └── exporter.ts          # JetBrains plugin scaffolding
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add vulnerability patterns to `src/patterns/vulnerabilityPatterns.ts` or `expandedPatterns.ts`
4. Run `npm run compile && npm run lint`
5. Open a Pull Request

**Adding a new pattern:**
```typescript
{
  type: 'Your Vulnerability Name',
  severity: 'critical',
  regex: /your-pattern/gi,
  languages: ['javascript', 'python'],
  message: 'Short description',
  explanation: 'Why this is dangerous and how attackers exploit it',
  fix: 'Step-by-step fix instructions',
  codeExample: '// Secure alternative code',
  cwe: 'CWE-XXX'
}
```

---

## License

MIT — see LICENSE file.

---

<div align="center">

**CodeGuard Copilot v0.5.0 — Intelligent Security Ecosystem**

Connected to Raven · Powered by attacker intelligence · Built for developers

</div>
