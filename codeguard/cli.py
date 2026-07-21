"""CodeGuard — CLI. The developer-facing command line interface."""
import sys
import os
import json
import argparse
import hashlib
import importlib.util
from pathlib import Path
from datetime import datetime

from .engine import CodeGuardEngine
from .output import format_text, format_json, format_sarif, format_markdown, format_html

ENV_THRESHOLDS = {
    "dev": "low",
    "staging": "high",
    "prod": "critical",
}


def main():
    parser = argparse.ArgumentParser(
        prog="codeguard",
        description="CodeGuard — Security analysis for your codebase. One engine, multiple workflows.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan files or directories for vulnerabilities")
    scan.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    scan.add_argument("--severity", "-s", choices=["critical", "high", "medium", "low"],
                       nargs="+", help="Filter by severity")
    scan.add_argument("--format", "-f", choices=["text", "json", "sarif", "markdown", "html"],
                       default="text", help="Output format")
    scan.add_argument("--output", "-o", help="Write output to file")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                       help="Exit non-zero if findings at this severity or above")
    scan.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output")
    scan.add_argument("--custom-rules", help="Path to .codeguard.json custom rules file")
    scan.add_argument("--env", choices=["dev", "staging", "prod"],
                       help="Environment context: dev=all, staging=high+, prod=critical+")
    scan.add_argument("--plugin", action="append", dest="plugins",
                       help="Path to plugin Python file (can be used multiple times)")
    scan.add_argument("--drift", action="store_true",
                       help="Compare with previous scan, show new/resolved findings")

    doctor = sub.add_parser("doctor", help="Check system health and configuration")
    doctor.add_argument("--fix", action="store_true", help="Attempt to fix detected issues")

    version = sub.add_parser("version", help="Show version and system info")

    config = sub.add_parser("config", help="Show or set configuration")
    config.add_argument("--show", action="store_true", help="Show current configuration")

    args = parser.parse_args()

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "doctor":
        _cmd_doctor(args)
    elif args.command == "version":
        _cmd_version()
    elif args.command == "config":
        _cmd_config(args)
    else:
        parser.print_help()
        sys.exit(0)


def _cmd_scan(args):
    engine = CodeGuardEngine()

    if args.custom_rules:
        count = engine.load_custom_patterns(args.custom_rules)
        if not args.quiet:
            print(f"Loaded {count} custom patterns")

    # Resolve severity filter from environment
    severity_filter = args.severity
    if args.env and not severity_filter:
        threshold = ENV_THRESHOLDS.get(args.env, "low")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        severity_filter = [s for s in sev_order if sev_order[s] <= sev_order[threshold]]
        if not args.quiet:
            print(f"  Environment: {args.env} (showing: {', '.join(severity_filter)})")

    path = args.path
    if os.path.isfile(path):
        findings = engine.scan_file(path, severity_filter)
    elif os.path.isdir(path):
        findings = engine.scan_directory(path, severity_filter)
    else:
        print(f"Error: {path} does not exist", file=sys.stderr)
        sys.exit(1)

    # Load and run plugins
    if args.plugins:
        for plugin_path in args.plugins:
            try:
                spec = importlib.util.spec_from_file_location("codeguard_plugin", plugin_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "analyze"):
                    extra = mod.analyze(path)
                    for e in extra:
                        findings.append(e)
                    if not args.quiet:
                        print(f"  Plugin {Path(plugin_path).name}: {len(extra)} findings")
            except Exception as e:
                print(f"  Plugin {plugin_path} failed: {e}", file=sys.stderr)

    # Security drift detection
    drift_changes = None
    if args.drift:
        drift_changes = _check_drift(findings, path, args.quiet)

    output = _format_findings(findings, args.format, path, drift_changes)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if not args.quiet:
            print(f"Report written to {args.output}")

    if args.format == "text":
        if args.quiet and findings:
            for f in findings:
                print(f"{f.file_path}:{f.line}: [{f.severity.upper()}] {f.message}")
        elif not args.quiet:
            print(output)
    else:
        print(output)

    if args.fail_on:
        fail_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = fail_order.get(args.fail_on, 0)
        for f in findings:
            if fail_order.get(f.severity, 9) <= threshold:
                if not args.quiet:
                    print(f"\nFailed: {f.severity}-severity finding detected. Exit code 1.", file=sys.stderr)
                sys.exit(1)

    if findings and not args.quiet and args.format == "text":
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        parts = [f"{c} {s}" for s, c in sorted(sev_counts.items())]
        print(f"\n{len(findings)} findings ({', '.join(parts)})")

    # Save scan state for drift
    _save_scan_state(findings, path)


def _check_drift(findings, scan_path, quiet):
    state_file = Path(scan_path if os.path.isfile(scan_path) else scan_path) / ".codeguard-state.json"
    if not state_file.exists():
        if not quiet:
            print("  Drift: no previous scan state found (first scan)")
        return None

    try:
        prev = json.loads(state_file.read_text())
        prev_keys = {(f["rule_id"], f["file_path"], f["line"]) for f in prev.get("findings", [])}
        curr_keys = {(f.rule_id, f.file_path, f.line) for f in findings}

        new_keys = curr_keys - prev_keys
        resolved_keys = prev_keys - curr_keys

        new_findings = [f for f in findings if (f.rule_id, f.file_path, f.line) in new_keys]
        resolved = [f for f in prev.get("findings", []) if (f["rule_id"], f["file_path"], f["line"]) in resolved_keys]

        if not quiet:
            print(f"  Drift: {len(new_findings)} new, {len(resolved)} resolved")

        return {"new": new_findings, "resolved": resolved}
    except Exception as e:
        if not quiet:
            print(f"  Drift check failed: {e}")
        return None


def _save_scan_state(findings, scan_path):
    state_file = Path(scan_path if os.path.isfile(scan_path) else scan_path) / ".codeguard-state.json"
    try:
        state_file.write_text(json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "findings": [{"rule_id": f.rule_id, "file_path": f.file_path, "line": f.line,
                          "severity": f.severity, "cwe": f.cwe, "message": f.message} for f in findings],
        }, indent=2))
    except Exception:
        pass


def _cmd_doctor(args):
    print("CodeGuard Doctor")
    print("===============")
    issues = []

    engine = CodeGuardEngine()
    patterns = engine.get_pattern_count()
    print(f"  Patterns loaded: {patterns}")
    if patterns == 0:
        issues.append("No patterns loaded — check patterns.json")

    langs = engine.get_supported_languages()
    print(f"  Supported languages: {len(langs)} ({', '.join(langs[:8])}...)")

    try:
        import json as _j
        print(f"  Python: OK ({sys.version.split()[0]})")
    except Exception:
        issues.append("Python import issue")

    ai_key = os.getenv("CODEGUARD_AI_KEY") or os.getenv("OPENAI_API_KEY")
    print(f"  AI provider: {'configured' if ai_key else 'not configured (optional)'}")

    raven_url = os.getenv("RAVEN_API_URL", "")
    print(f"  Raven: {'configured' if raven_url else 'not configured (optional)'}")

    git_hook = Path(".git/hooks/pre-commit").exists()
    print(f"  Pre-commit hook: {'installed' if git_hook else 'not installed'}")

    # Plugins check
    plugin_dir = Path("plugins")
    if plugin_dir.is_dir():
        plugins = list(plugin_dir.glob("*.py"))
        print(f"  Plugins: {len(plugins)} found ({', '.join(p.name for p in plugins)})")

    if issues:
        print(f"\n{len(issues)} issue(s) found:")
        for i in issues:
            print(f"  - {i}")
        if args.fix:
            print("  Auto-fix not yet implemented")
    else:
        print("\n  All checks passed.")


def _cmd_version():
    from . import __version__
    engine = CodeGuardEngine()
    print(f"CodeGuard v{__version__}")
    print(f"  Patterns: {engine.get_pattern_count()}")
    print(f"  Languages: {', '.join(engine.get_supported_languages())}")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  Environments: dev, staging, prod")
    print(f"  Plugins: --plugin flag supported")
    print(f"  Drift: --drift flag supported")


def _cmd_config(args):
    print("CodeGuard Configuration")
    print("======================")
    print(f"  CODEGUARD_AI_KEY: {'****' if os.getenv('CODEGUARD_AI_KEY') else '(not set)'}")
    print(f"  CODEGUARD_AI_URL: {os.getenv('CODEGUARD_AI_URL', 'https://api.openai.com/v1')}")
    print(f"  CODEGUARD_AI_MODEL: {os.getenv('CODEGUARD_AI_MODEL', 'gpt-4o-mini')}")
    print(f"  RAVEN_API_URL: {os.getenv('RAVEN_API_URL', '(not set)')}")
    print(f"  Env thresholds: dev=all, staging=high+, prod=critical+")
    print(f"  Custom rules: .codeguard.json (project root)")
    print(f"  Plugins: --plugin <file.py> or plugins/ directory")
    print(f"  Drift: --drift to track changes")


def _format_findings(findings, fmt, scan_path, drift_changes=None):
    if fmt == "json":
        return format_json(findings, scan_path)
    elif fmt == "sarif":
        return format_sarif(findings, scan_path)
    elif fmt == "markdown":
        return format_markdown(findings, scan_path)
    elif fmt == "html":
        return format_html(findings, scan_path)
    else:
        return format_text(findings, scan_path)


if __name__ == "__main__":
    main()
