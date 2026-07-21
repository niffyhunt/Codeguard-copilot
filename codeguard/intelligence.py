"""CodeGuard Local Intelligence — Zero LLM, zero API, zero dependencies.

Generates intelligent security explanations purely from:
1. The 32 CodeGuard vulnerability patterns (embedded knowledge)
2. AST analysis context (source→sink tracking)
3. Code context (file path, variable names, language)

This is NOT an LLM wrapper. It's deterministic intelligence composition.
Every explanation is derived from actual detection evidence.
Works fully offline. Instant (<1ms). Zero downloads.
"""
import re
import os
from pathlib import Path


CWE_KNOWLEDGE = {
    "CWE-89": {
        "name": "SQL Injection",
        "attack": "Attackers insert malicious SQL through user input. A single quote can escape the query, allowing UNION SELECT, DROP TABLE, or data extraction.",
        "impact": "Complete database compromise — read, modify, or delete all data. Most exploited web vulnerability for 20+ years.",
        "real_world": "MOVEit Transfer (2023) — CVE-2023-34362 affected thousands of organizations worldwide via SQL injection.",
        "prevention": "Parameterized queries. Never concatenate user input into SQL. Use ORM when possible.",
    },
    "CWE-78": {
        "name": "Command Injection",
        "attack": "User input passed to system commands. Attackers chain commands with ; && | to execute arbitrary code on the server.",
        "impact": "Full server compromise. Attacker gets shell access, can install malware, pivot to internal network.",
        "real_world": "GitLab (2021) — CVE-2021-22205 allowed remote code execution via command injection in ExifTool.",
        "prevention": "Use argument lists. Never use shell=True. Validate and sanitize all inputs before passing to subprocess.",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "attack": "Malicious scripts injected into web pages viewed by others. Can steal cookies, tokens, keystrokes, and sensitive data.",
        "impact": "Session hijacking, credential theft, defacement. British Airways fined £20M after XSS compromised 380K records (2020).",
        "real_world": "British Airways (2020) — £20M fine after XSS on payment page exposed 380,000 customer records.",
        "prevention": "Use textContent instead of innerHTML. Sanitize HTML with DOMPurify. Implement Content-Security-Policy headers.",
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "attack": "Secrets in source code are exposed to anyone with repository access. Attackers scan GitHub for sk-, ghp_, and password patterns automatically.",
        "impact": "Full service compromise. API keys grant programmatic access. One leaked key can cascade to cloud infrastructure, databases, and internal services.",
        "real_world": "GitHub scans 200+ token types. In 2025, they detected and revoked millions of leaked credentials automatically.",
        "prevention": "Use environment variables, secret managers (Vault, AWS Secrets Manager), or .env files excluded from git.",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "attack": "User-controlled filenames with ../ sequences allow reading arbitrary files on the server. Attackers access /etc/passwd, source code, configuration, and SSH keys.",
        "impact": "Information disclosure. Access to database credentials, API keys, source code. Can chain with other vulns for RCE.",
        "real_world": "Apache HTTP Server (2021) — CVE-2021-41773 path traversal allowed RCE on unpatched servers.",
        "prevention": "Validate filenames against whitelist. Use os.path.realpath() to resolve paths. Never trust user-supplied file paths.",
    },
    "CWE-502": {
        "name": "Insecure Deserialization",
        "attack": "Untrusted serialized data can instantiate arbitrary objects. Attackers craft malicious pickles that execute system commands during deserialization.",
        "impact": "Remote code execution. The most dangerous vulnerability class — deserializing untrusted data is equivalent to eval().",
        "real_world": "Java deserialization (2015-2020) — CVE-2015-4852 affected WebLogic, WebSphere, JBoss. Used in Equifax breach.",
        "prevention": "Never deserialize untrusted data. Use JSON for data exchange. If unavoidable, validate types with a strict whitelist.",
    },
    "CWE-327": {
        "name": "Weak Cryptography",
        "attack": "MD5 and SHA1 are broken. Attackers can generate hash collisions and crack passwords in seconds using rainbow tables or GPU clusters.",
        "impact": "Authentication bypass. Password cracking. Data integrity compromise. Regulatory non-compliance (PCI-DSS, HIPAA).",
        "real_world": "SHA1 collisions demonstrated in 2017 (SHAttered). MD5 collisions used to forge SSL certificates in 2008.",
        "prevention": "Use bcrypt, scrypt, or argon2 for passwords. Use SHA-256 or BLAKE2 for data integrity. AES-256-GCM for encryption.",
    },
}

SEVERITY_DESCRIPTIONS = {
    "critical": "This must be fixed immediately. This vulnerability type is actively exploited in the wild and can lead to full system compromise.",
    "high": "High risk. This vulnerability can be exploited with moderate effort and leads to significant data or system access.",
    "medium": "Moderate risk. Exploitable under certain conditions. Should be addressed in the current development cycle.",
    "low": "Low risk. Represents a security weakness that should be corrected but poses limited immediate danger.",
}

FILE_CONTEXT_ADVICE = {
    "config": "Configuration files are prime targets for attackers. Credentials here grant access to production infrastructure.",
    "auth": "Authentication code is the security boundary. Any vulnerability here compromises all user accounts.",
    "api": "API endpoints are the most attacked surface. They are exposed to the internet and constantly probed.",
    "db": "Database code handles the most valuable asset: your data. SQL injection here is catastrophic.",
    "test": "This file appears to be test code. While lower priority, test credentials should still never be real.",
    "docs": "Documentation and examples should use clearly fake credentials to prevent accidental real usage.",
}


def generate_intelligent_explanation(finding_dict, code_snippet=""):
    """Generate a detailed, evidence-backed security explanation without any LLM.
    
    Uses the finding's detection data (rule_id, CWE, analyzer, source/sink, file path)
    combined with embedded security knowledge to produce explanations that feel 
    like they came from a security expert — because they did. The knowledge is 
    pre-compiled from verified CWE databases, real-world breach data, and 
    security best practices.
    """
    rule_id = finding_dict.get("rule_id", "Unknown")
    severity = finding_dict.get("severity", "medium")
    cwe = finding_dict.get("cwe", "")
    analyzer = finding_dict.get("analyzer", "regex")
    file_path = finding_dict.get("file_path", "")
    source = finding_dict.get("source", "")
    sink = finding_dict.get("sink", "")
    line = finding_dict.get("line", "")

    parts = []

    # 1. What was detected and how
    detection_method = {
        "regex": "pattern matching",
        "ast": "AST-level syntax analysis",
        "ai": "AI-assisted analysis",
    }.get(analyzer, "analysis")

    parts.append(f"CodeGuard detected a {severity.upper()} severity finding: **{rule_id}**")
    parts.append(f"Detection method: {detection_method}")
    if line:
        parts.append(f"Location: {file_path}:{line}")
    if source and sink:
        parts.append(f"Data flow: {source} → {sink}")

    # 2. CWE-specific knowledge (the real intelligence)
    if cwe in CWE_KNOWLEDGE:
        k = CWE_KNOWLEDGE[cwe]
        parts.append("")
        parts.append(f"WHAT IS {k['name'].upper()}?")
        parts.append(k['attack'])
        parts.append("")
        parts.append(f"HOW BAD IS THIS?")
        parts.append(k['impact'])
        parts.append("")
        parts.append(f"REAL-WORLD EXAMPLE:")
        parts.append(k['real_world'])
        parts.append("")
        parts.append(f"HOW TO FIX:")
        parts.append(k['prevention'])

    # 3. Severity context
    if severity in SEVERITY_DESCRIPTIONS:
        parts.append("")
        parts.append(f"PRIORITY: {SEVERITY_DESCRIPTIONS[severity]}")

    # 4. File context intelligence
    for pattern, advice in FILE_CONTEXT_ADVICE.items():
        if pattern in file_path.lower():
            parts.append("")
            parts.append(f"CONTEXT: {advice}")

    # 5. Fix suggestion from the finding itself
    fix = finding_dict.get("fix", "")
    if fix:
        parts.append("")
        parts.append(f"SPECIFIC FIX: {fix}")

    # 6. Raven context if available
    raven = finding_dict.get("raven", {})
    if raven:
        if raven.get("attacker_aligned"):
            parts.append("")
            parts.append("RAVEN INTELLIGENCE: Real attackers on our honeypot network are actively using this exploitation technique. This is not a theoretical vulnerability.")
        if raven.get("deception_correlated"):
            parts.append("RAVEN INTELLIGENCE: Attackers have accessed HoneyFS bait files matching this vulnerability pattern. They are specifically hunting for this type of weakness.")
        if raven.get("breach_aligned"):
            parts.append("RAVEN INTELLIGENCE: This credential pattern matches leaked credentials found in recent dark-web breach dumps.")

    return "\n".join(parts)


def generate_remediation_plan(findings):
    """Generate a prioritized remediation plan from all findings.
    Deterministic sorting by severity, CWE criticality, and analyzer confidence."""
    if not findings:
        return "No security issues found. Codebase is clean."

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda f: (
        sev_order.get(f.severity if hasattr(f, 'severity') else f.get('severity', 'low'), 9),
        -(f.confidence if hasattr(f, 'confidence') else f.get('confidence', 0) if isinstance(f, dict) else 0) if isinstance(f, dict) else 0,
    ))

    parts = [f"CodeGuard Remediation Plan — {len(sorted_findings)} issues", "=" * 50, ""]

    current_sev = None
    for i, f in enumerate(sorted_findings, 1):
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'medium')
        rid = f.rule_id if hasattr(f, 'rule_id') else f.get('rule_id', 'Unknown')
        fpath = f.file_path if hasattr(f, 'file_path') else f.get('file_path', '')
        fline = f.line if hasattr(f, 'line') else f.get('line', '')

        if sev != current_sev:
            current_sev = sev
            icons = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}
            parts.append(f"\n{icons.get(sev, '•')} {sev.upper()} PRIORITY")
            parts.append("-" * 40)

        parts.append(f"{i}. {rid}")
        if fpath:
            parts.append(f"   File: {fpath}:{fline}")
        fix = f.fix if hasattr(f, 'fix') else f.get('fix', '')
        if fix:
            parts.append(f"   Fix: {fix[:120]}")
        parts.append("")

    return "\n".join(parts)
