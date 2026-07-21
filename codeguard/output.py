"""CodeGuard — Output formatters: text, JSON, SARIF, Markdown."""
import json
from datetime import datetime


def format_text(findings, scan_path):
    if not findings:
        return f"CodeGuard scan of {scan_path}\nNo security issues found.\n"

    lines = [f"CodeGuard Scan Report — {scan_path}", "=" * 60, ""]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    grouped = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    sev_icons = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}

    for sev in sorted(grouped, key=lambda s: sev_order.get(s, 9)):
        lines.append(f"{sev_icons.get(sev, '•')} {sev.upper()} ({len(grouped[sev])})")
        lines.append("-" * 60)
        for f in grouped[sev]:
            lines.append(f"  {f.file_path}:{f.line}:{f.column}")
            lines.append(f"  Rule: {f.rule_id}")
            lines.append(f"  Message: {f.message}")
            if f.cwe:
                lines.append(f"  CWE: {f.cwe}")
            lines.append("")

    return "\n".join(lines)


def format_json(findings, scan_path):
    return json.dumps({
        "tool": "CodeGuard",
        "scan_path": scan_path,
        "timestamp": datetime.utcnow().isoformat(),
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def format_sarif(findings, scan_path):
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _sev_to_sarif(f.severity),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line, "startColumn": f.column}
                }
            }],
            "properties": {
                "cwe": f.cwe,
                "fix": f.fix,
                "confidence": f.confidence,
            }
        })

    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeGuard", "semanticVersion": "0.2.0"}},
            "results": results,
        }]
    }, indent=2)


def format_markdown(findings, scan_path):
    lines = [f"# CodeGuard Scan Report — `{scan_path}`", "",
             f"**Total findings:** {len(findings)}  ",
             f"**Scanned at:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", ""]

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    grouped = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    for sev in sorted(grouped, key=lambda s: sev_order.get(s, 9)):
        lines.append(f"## {sev.upper()} ({len(grouped[sev])})")
        lines.append("")
        for f in grouped[sev]:
            lines.append(f"### {f.rule_id}")
            lines.append(f"- **File:** `{f.file_path}:{f.line}`")
            lines.append(f"- **Message:** {f.message}")
            if f.cwe:
                lines.append(f"- **CWE:** [{f.cwe}](https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html)")
            lines.append(f"- **Fix:** {f.fix}")
            lines.append("")

    return "\n".join(lines)


def _sev_to_sarif(severity):
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "warning")
