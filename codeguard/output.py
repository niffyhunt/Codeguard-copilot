"""CodeGuard — Output formatters: text, JSON, SARIF, Markdown, HTML."""
import json
import os
from datetime import datetime, timezone


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
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
             f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", ""]

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


def format_html(findings, scan_path):
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    grouped = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    sev_colors = {"critical": "#ff1a1a", "high": "#ff6600", "medium": "#ffaa00", "low": "#88cc00"}
    sev_icons = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}

    cards = ""
    for sev in sorted(grouped, key=lambda s: sev_order.get(s, 9)):
        for f in grouped[sev]:
            c = sev_colors.get(sev, "#888")
            cards += f"""
            <div class="finding" style="border-left: 4px solid {c}; margin: 12px 0; padding: 16px; background: #1a1a2e; border-radius: 8px;">
              <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                <span style="font-size: 18px;">{sev_icons.get(sev, '•')}</span>
                <span style="color: {c}; font-weight: 700; font-family: monospace; font-size: 14px;">{sev.upper()}</span>
                <span style="color: #666; font-family: monospace; font-size: 12px;">{f.rule_id}</span>
                {f'<span style="color: #888; font-family: monospace; font-size: 11px; background: #0a0a14; padding: 2px 8px; border-radius: 4px;">{f.cwe}</span>' if f.cwe else ''}
              </div>
              <div style="color: #aaa; font-family: monospace; font-size: 12px; margin-bottom: 6px;">{f.file_path}:{f.line}:{f.column}</div>
              <div style="color: #ddd; font-size: 13px;">{f.message}</div>
              {f'<div style="color: #888; font-size: 12px; margin-top: 6px; padding: 8px; background: #0a0a14; border-radius: 4px; font-family: monospace;">Fix: {f.fix}</div>' if f.fix else ''}
            </div>"""

    severity_summary = ""
    for sev in sorted(grouped, key=lambda s: sev_order.get(s, 9)):
        severity_summary += f'<span style="color: {sev_colors.get(sev, "#888")}; font-weight: 700; margin-right: 16px;">{sev_icons.get(sev, "•")} {len(grouped[sev])} {sev.upper()}</span>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CodeGuard Report — {os.path.basename(scan_path)}</title>
<style>* {{margin:0;padding:0;box-sizing:border-box;}}
body {{background:#0a0a14;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;}}
.header {{margin-bottom:32px;}}
h1 {{color:#fff;font-size:24px;font-weight:700;}}
.stats {{display:flex;gap:24px;margin:16px 0;}}
.stat {{background:#1a1a2e;padding:12px 20px;border-radius:8px;}}
.stat-label {{color:#666;font-size:11px;text-transform:uppercase;letter-spacing:1px;}}
.stat-value {{color:#00ff88;font-size:22px;font-weight:700;font-family:monospace;}}
.summary {{margin:20px 0;padding:16px;background:#0f0f1f;border-radius:8px;}}
.timestamp {{color:#555;font-size:12px;margin-top:24px;}}
</style></head>
<body>
<div class="header">
  <h1>🛡️ CodeGuard Security Report</h1>
  <div style="color:#888;font-size:13px;margin-top:4px;">Scan: <code>{scan_path}</code></div>
  <div class="stats">
    <div class="stat"><div class="stat-label">Findings</div><div class="stat-value">{len(findings)}</div></div>
    <div class="stat"><div class="stat-label">Critical</div><div class="stat-value" style="color:#ff1a1a">{len(grouped.get('critical',[]))}</div></div>
    <div class="stat"><div class="stat-label">High</div><div class="stat-value" style="color:#ff6600">{len(grouped.get('high',[]))}</div></div>
    <div class="stat"><div class="stat-label">Medium</div><div class="stat-value" style="color:#ffaa00">{len(grouped.get('medium',[]))}</div></div>
  </div>
</div>
<div class="summary">{severity_summary}</div>
<div id="findings">{cards}</div>
<div class="timestamp">Generated by CodeGuard v0.3.3 — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
</body></html>"""


def _sev_to_sarif(severity):
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "warning")
