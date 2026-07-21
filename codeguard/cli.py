"""CodeGuard — CLI. The developer-facing command line interface."""
import sys
import os
import json
import argparse
from pathlib import Path

from .engine import CodeGuardEngine
from .output import format_text, format_json, format_sarif, format_markdown


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
    scan.add_argument("--format", "-f", choices=["text", "json", "sarif", "markdown"],
                       default="text", help="Output format")
    scan.add_argument("--output", "-o", help="Write output to file")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                       help="Exit non-zero if findings at this severity or above")
    scan.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output")
    scan.add_argument("--custom-rules", help="Path to .codeguard.json custom rules file")

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
    severity_filter = args.severity

    if args.custom_rules:
        count = engine.load_custom_patterns(args.custom_rules)
        if not args.quiet:
            print(f"Loaded {count} custom patterns")

    path = args.path
    if os.path.isfile(path):
        findings = engine.scan_file(path, severity_filter)
    elif os.path.isdir(path):
        findings = engine.scan_directory(path, severity_filter)
    else:
        print(f"Error: {path} does not exist", file=sys.stderr)
        sys.exit(1)

    output = _format_findings(findings, args.format, path)

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


def _cmd_config(args):
    print("CodeGuard Configuration")
    print("======================")
    print(f"  CODEGUARD_AI_KEY: {'****' if os.getenv('CODEGUARD_AI_KEY') else '(not set)'}")
    print(f"  CODEGUARD_AI_URL: {os.getenv('CODEGUARD_AI_URL', 'https://api.openai.com/v1')}")
    print(f"  CODEGUARD_AI_MODEL: {os.getenv('CODEGUARD_AI_MODEL', 'gpt-4o-mini')}")
    print(f"  RAVEN_API_URL: {os.getenv('RAVEN_API_URL', '(not set)')}")
    print(f"\n  Custom rules: .codeguard.json (project root)")


def _format_findings(findings, fmt, scan_path):
    if fmt == "json":
        return format_json(findings, scan_path)
    elif fmt == "sarif":
        return format_sarif(findings, scan_path)
    elif fmt == "markdown":
        return format_markdown(findings, scan_path)
    else:
        return format_text(findings, scan_path)


if __name__ == "__main__":
    main()
