"""CodeGuard — Third-party integrations: GitHub, GitLab, Slack, SIEM, SOAR."""
import json
import os
import subprocess
from datetime import datetime


def github_annotation(findings, level="warning"):
    """Generate GitHub Actions annotations from findings."""
    for f in findings:
        sev = f.severity
        lvl = "error" if sev == "critical" else "warning"
        if lvl == "warning" and level == "error":
            continue
        print(f"::{lvl} file={f.file_path},line={f.line},col={f.column}::{f.rule_id}: {f.message}")


def gitlab_artifact(findings, output_file="codeguard-report.json"):
    """Write GitLab CI-compatible artifact."""
    data = {
        "tool": "CodeGuard",
        "timestamp": datetime.utcnow().isoformat(),
        "findings": [f.to_dict() for f in findings],
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"CodeGuard: {len(findings)} findings → {output_file}")


def slack_message(findings, webhook_url=None):
    """Post findings summary to Slack webhook."""
    webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return

    sev_count = {}
    for f in findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"CodeGuard Scan — {len(findings)} findings"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Critical:* {sev_count.get('critical', 0)}"},
            {"type": "mrkdwn", "text": f"*High:* {sev_count.get('high', 0)}"},
            {"type": "mrkdwn", "text": f"*Medium:* {sev_count.get('medium', 0)}"},
            {"type": "mrkdwn", "text": f"*Low:* {sev_count.get('low', 0)}"},
        ]},
    ]

    top_findings = [f for f in findings if f.severity in ("critical", "high")][:5]
    if top_findings:
        text = "\n".join([f"• {f.file_path}:{f.line} — {f.message}" for f in top_findings])
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Top findings:*\n{text}"}})

    try:
        import urllib.request
        data = json.dumps({"blocks": blocks}).encode()
        req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"Slack notification failed: {e}", file=__import__("sys").stderr)


def sonarqube_generic(findings, output_file="codeguard-sonar.json"):
    """Export in SonarQube generic issue format."""
    issues = []
    for f in findings:
        issues.append({
            "engineId": "codeguard",
            "ruleId": f.rule_id,
            "severity": f.severity.upper(),
            "type": "VULNERABILITY",
            "primaryLocation": {
                "message": f.message,
                "filePath": f.file_path,
                "textRange": {"startLine": f.line, "startColumn": f.column},
            },
        })
    with open(output_file, "w") as fh:
        json.dump({"issues": issues}, fh, indent=2)


def junit_xml(findings, output_file="codeguard-junit.xml"):
    """Export findings as JUnit XML for CI/CD dashboard integration."""
    sev_count = {}
    for f in findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1

    testcases = []
    for f in findings[:50]:
        testcases.append(
            f'    <testcase name="{f.rule_id} — {f.file_path}:{f.line}">\n'
            f'      <failure message="{f.message}" type="{f.severity}">{f.explanation}</failure>\n'
            f'    </testcase>'
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="CodeGuard" tests="{len(findings)}" failures="{sev_count.get("critical", 0) + sev_count.get("high", 0)}">\n'
        + "\n".join(testcases) +
        "\n</testsuite>"
    )

    with open(output_file, "w") as fh:
        fh.write(xml)
