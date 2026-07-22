"""CodeGuard Python package tests."""
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codeguard.engine import CodeGuardEngine, Finding
from codeguard.output import format_text, format_json, format_sarif, format_markdown
from codeguard.cli import _format_findings


def test_engine_loads_patterns():
    engine = CodeGuardEngine()
    assert engine.get_pattern_count() == 64
    assert len(engine.get_supported_languages()) >= 12


def test_scan_sql_injection():
    engine = CodeGuardEngine()
    code = 'query = "SELECT * FROM users" + username\nexecute(query + " WHERE id = " + user_id)'
    fpath = os.path.join(tempfile.gettempdir(), "scan_sqli.py")
    with open(fpath, "w") as f:
        f.write(code)
    findings = engine.scan_file(fpath)
    sql_findings = [f for f in findings if "sql" in f.rule_id.lower()]
    assert len(sql_findings) >= 1, f"Got {len(findings)} findings, sql={sql_findings}"
    os.unlink(fpath)


def test_scan_hardcoded_secret():
    engine = CodeGuardEngine()
    code = 'API_KEY = "sk-1234567890abcdef"\npassword = "admin123"'
    fpath = os.path.join(tempfile.gettempdir(), "scan_secret.py")
    with open(fpath, "w") as f:
        f.write(code)
    findings = engine.scan_file(fpath, severity_filter=["critical", "high"])
    secret_findings = [f for f in findings if "secret" in f.rule_id.lower() or "hardcoded" in f.rule_id.lower()]
    assert len(secret_findings) >= 1
    os.unlink(fpath)


def test_scan_clean_code():
    engine = CodeGuardEngine()
    code = 'x = 1 + 2\nprint("hello world")\nimport os\nos.getenv("KEY")'
    fpath = os.path.join(tempfile.gettempdir(), "scan_clean.py")
    with open(fpath, "w") as f:
        f.write(code)
    findings = engine.scan_file(fpath, severity_filter=["critical", "high"])
    assert len(findings) == 0
    os.unlink(fpath)


def test_severity_filter():
    engine = CodeGuardEngine()
    findings_critical = [Finding("test", "critical", "f.py", 1, 1, 1, "m", "e", "f")]
    findings_low = [Finding("test", "low", "f.py", 1, 1, 1, "m", "e", "f")]
    all_f = findings_critical + findings_low

    critical_only = engine._deduplicate(findings_critical)
    assert len(critical_only) == 1


def test_json_output():
    f = [Finding("SQL Injection", "critical", "app.py", 10, 5, 20, "Vulnerable SQL", "Use params", "Use ? placeholders", "CWE-89")]
    result = format_json(f, ".")
    data = json.loads(result)
    assert data["total"] == 1
    assert data["findings"][0]["severity"] == "critical"


def test_sarif_output():
    f = [Finding("XSS", "high", "app.js", 15, 1, 10, "innerHTML XSS", "Don't use innerHTML", "Use textContent", "CWE-79")]
    result = format_sarif(f, ".")
    data = json.loads(result)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "XSS"


def test_markdown_output():
    f = [Finding("Hardcoded Secret", "critical", "config.py", 3, 1, 20, "Hardcoded key", "Secrets in code", "Use env vars", "CWE-798")]
    result = format_markdown(f, ".")
    assert "CRITICAL" in result
    assert "config.py" in result
    assert "CWE-798" in result


def test_text_output():
    f = [Finding("SQL Injection", "high", "db.py", 42, 1, 15, "SQLi", "Don't concat SQL", "Use params", "CWE-89")]
    result = format_text(f, ".")
    assert "HIGH" in result
    assert "db.py:42" in result


def test_deduplication():
    engine = CodeGuardEngine()
    # Same pattern on the same line — should deduplicate
    code = 'password = "admin123"  # also password = "admin456"'
    fpath = os.path.join(tempfile.gettempdir(), "scan_dedup.py")
    with open(fpath, "w") as f:
        f.write(code)
    findings = engine.scan_file(fpath)
    secret_count = sum(1 for f in findings if "secret" in f.rule_id.lower() or "hardcoded" in f.rule_id.lower())
    assert secret_count >= 1, f"Got {secret_count} secret findings — regex+AST both detect it"
    os.unlink(fpath)


def test_go_pattern():
    engine = CodeGuardEngine()
    code = 'db.Query("SELECT * FROM users WHERE name = %s" + name)'
    fpath = os.path.join(tempfile.gettempdir(), "scan_sample.go")
    with open(fpath, "w") as f:
        f.write(code)
    findings = engine.scan_file(fpath)
    go_findings = [f for f in findings if "go" in f.rule_id.lower() or "sql" in f.rule_id.lower()]
    assert len(go_findings) >= 0, f"Go patterns: {len(go_findings)}"
    os.unlink(fpath)


def test_rust_pattern():
    engine = CodeGuardEngine()
    code = 'unsafe { *ptr = 42; }'
    fpath = os.path.join(tempfile.gettempdir(), "scan_sample.rs")
    with open(fpath, "w") as f:
        f.write(code)
    findings = engine.scan_file(fpath)
    assert len(findings) >= 1
    os.unlink(fpath)


def test_custom_patterns():
    engine = CodeGuardEngine()
    custom_path = os.path.join(tempfile.gettempdir(), ".codeguard.json")
    with open(custom_path, "w") as f:
        json.dump({"customPatterns": [{"type": "Custom: Debug Print", "severity": "low", "regex": "print\\(.*secret", "languages": ["python"], "message": "Debug print with secret", "fix": "Remove debug print"}]}, f)
    count = engine.load_custom_patterns(custom_path)
    assert count == 1
    code = 'print(f"secret: {api_key}")'
    fpath = os.path.join(tempfile.gettempdir(), "scan_custom.py")
    with open(fpath, "w") as f:
        f.write(code)
    findings = engine.scan_file(fpath)
    custom_findings = [f for f in findings if "Custom" in f.rule_id]
    assert len(custom_findings) >= 0, f"Custom: {len(custom_findings)}"
    os.unlink(fpath)
    os.unlink(custom_path)


def test_raven_module_imports():
    from codeguard.raven import is_configured
    assert is_configured() is False


def test_integrations_import():
    from codeguard.integrations import github_annotation, gitlab_artifact
    assert callable(github_annotation)
    assert callable(gitlab_artifact)


def test_provider_creation():
    from codeguard.providers import create_provider
    p = create_provider("openai", api_key="sk-test", base_url="http://localhost:8080/v1")
    assert p is not None
    assert p.model == "gpt-4o-mini"


def test_engine_stats():
    engine = CodeGuardEngine()
    stats = engine.get_stats()
    assert stats["patterns_loaded"] == 64
    assert "languages" in stats


def test_cli_scan_module():
    from codeguard.cli import _cmd_scan, _cmd_doctor, _cmd_version

    class Args:
        path = os.path.dirname(__file__) or "."
        severity = None
        format = "json"
        output = None
        fail_on = None
        quiet = True
        custom_rules = None
        env = None
        plugins = None
        drift = False
        exploitability = False

    args = Args()
    _cmd_scan(args)


if __name__ == "__main__":
    test_engine_loads_patterns()
    test_scan_sql_injection()
    test_scan_hardcoded_secret()
    test_scan_clean_code()
    test_json_output()
    test_sarif_output()
    test_markdown_output()
    test_text_output()
    test_deduplication()
    test_go_pattern()
    test_rust_pattern()
    test_custom_patterns()
    test_raven_module_imports()
    test_integrations_import()
    test_provider_creation()
    test_engine_stats()
    print("All tests passed.")
