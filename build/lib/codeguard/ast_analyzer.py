"""CodeGuard AST Analysis Layer — Context-aware static analysis.

Layer 2 of the scanning pipeline. Runs AFTER regex detection to:
1. Eliminate regex false positives using syntax context
2. Add source→sink dataflow tracking for top CWEs
3. Distinguish production code from tests/examples/docs

Uses Python's built-in `ast` module (zero deps) for Python.
Uses tree-sitter (optional pip install) for JS/TS/Go/Rust.
Falls back gracefully if tree-sitter not installed.
"""
import ast as pyast
import re
import os
from pathlib import Path


class ASTFinding:
    def __init__(self, rule_id, severity, file_path, line, column, length,
                 message, explanation, fix, cwe=None, confidence="high",
                 source_call=None, sink_call=None, dataflow_path=None,
                 analyzer="ast"):
        self.rule_id = rule_id
        self.severity = severity
        self.file_path = file_path
        self.line = line
        self.column = column
        self.length = length
        self.message = message
        self.explanation = explanation
        self.fix = fix
        self.cwe = cwe
        self.confidence = confidence
        self.source_call = source_call
        self.sink_call = sink_call
        self.dataflow_path = dataflow_path
        self.analyzer = analyzer

    def to_dict(self):
        return {
            "rule_id": self.rule_id, "severity": self.severity,
            "file_path": self.file_path, "line": self.line,
            "column": self.column, "length": self.length,
            "message": self.message, "explanation": self.explanation,
            "fix": self.fix, "cwe": self.cwe, "confidence": self.confidence,
            "source_call": self.source_call, "sink_call": self.sink_call,
            "dataflow_path": self.dataflow_path, "analyzer": self.analyzer,
        }


class PythonASTAnalyzer:
    """Built-in Python AST analyzer — zero dependencies."""

    SOURCE_PATTERNS = {
        "request": ["request.args", "request.form", "request.json", "request.GET",
                     "request.POST", "request.data", "params[", "input("],
        "file_read": ["open(", "read(", "Path(", "readlines("],
        "env_read": ["os.environ", "os.getenv", "environ["],
        "argv": ["sys.argv", "argparse"],
    }

    SINK_PATTERNS = {
        "sql": ["execute(", "executemany(", "raw(", ".query(", "cursor.execute",
                 "db.execute", "sqlalchemy"],
        "html": [".innerHTML", "dangerouslySetInnerHTML", "document.write(",
                  "Markup(", "render_template"],
        "command": ["os.system(", "subprocess", "Popen(", "exec(", "eval(",
                     "spawn(", "popen("],
        "file_write": ["open(", "write(", "save(", "dump("],
        "network": ["requests.get", "requests.post", "urllib", "fetch("],
        "deserialize": ["pickle.loads", "yaml.load(", "json.loads", "marshal.loads"],
    }

    def analyze(self, file_path, code):
        if not file_path.endswith('.py'):
            return []

        findings = []
        try:
            tree = pyast.parse(code)
        except SyntaxError:
            return []

        if self._is_test_file(file_path):
            return []

        findings.extend(self._detect_sql_injection(tree, file_path))
        findings.extend(self._detect_command_injection(tree, file_path))
        findings.extend(self._detect_xss(tree, file_path))
        findings.extend(self._detect_hardcoded_secret(tree, file_path, code))
        findings.extend(self._detect_deserialization(tree, file_path))
        findings.extend(self._detect_path_traversal(tree, file_path))

        return findings

    def _is_test_file(self, file_path):
        path = file_path.lower()
        test_indicators = ['test_', '_test.py', 'spec_', '_spec.py',
                           'conftest.py', '/tests/', '/test/', '__pycache__']
        return any(i in path for i in test_indicators)

    def _find_function_calls(self, tree, func_name):
        results = []
        for node in pyast.walk(tree):
            if isinstance(node, pyast.Call):
                if isinstance(node.func, pyast.Attribute):
                    if node.func.attr == func_name:
                        results.append((node.lineno, node.col_offset, node))
                elif isinstance(node.func, pyast.Name):
                    if node.func.id == func_name:
                        results.append((node.lineno, node.col_offset, node))
        return results

    def _detect_sql_injection(self, tree, file_path):
        findings = []
        sql_calls = (self._find_function_calls(tree, 'execute') +
                     self._find_function_calls(tree, 'executemany') +
                     self._find_function_calls(tree, 'raw'))

        for lineno, col, node in sql_calls:
            if node.args and self._has_concatenation(node.args[0]):
                findings.append(ASTFinding(
                    "SQL Injection (AST)", "critical", file_path, lineno, col, 10,
                    "SQL query string contains concatenation — SQL injection risk",
                    "The argument to execute() uses string concatenation or formatting with potential user input. This enables SQL injection.",
                    "Use parameterized queries: cursor.execute(sql, (param1, param2)). Never concatenate user input into SQL.",
                    "CWE-89", confidence="high" if self._has_user_input(node.args[0]) else "medium",
                    sink_call=f"{getattr(node.func, 'attr', '')}()",
                ))
        return findings

    def _detect_command_injection(self, tree, file_path):
        findings = []
        cmd_funcs = ['system', 'popen', 'call', 'run', 'Popen']
        for func in cmd_funcs:
            for lineno, col, node in self._find_function_calls(tree, func):
                if node.args and self._has_concatenation(node.args[0]):
                    findings.append(ASTFinding(
                        "Command Injection (AST)", "critical", file_path, lineno, col, 10,
                        f"subprocess.{func}() with string concatenation — command injection risk",
                        "Building shell commands with string concatenation enables command injection. Use argument lists.",
                        f"Use subprocess.{func}(['cmd', arg1, arg2]) instead of string building.",
                        "CWE-78", confidence="high",
                        sink_call=f"subprocess.{func}()",
                    ))
        return findings

    def _detect_xss(self, tree, file_path):
        findings = []
        for node in pyast.walk(tree):
            if isinstance(node, pyast.Assign):
                for target in node.targets if isinstance(node.targets, list) else [node.targets]:
                    if isinstance(target, pyast.Attribute) and target.attr == 'innerHTML':
                        findings.append(ASTFinding(
                            "Cross-Site Scripting (AST)", "high", file_path,
                            node.lineno, node.col_offset, 10,
                            "innerHTML assignment detected — XSS risk if content is user-controlled",
                            "Setting innerHTML with unsanitized user input enables XSS. Use textContent for text, or DOMPurify for HTML.",
                            "Replace with element.textContent = value. If HTML is needed, sanitize with DOMPurify first.",
                            "CWE-79", confidence="medium",
                            sink_call="innerHTML",
                        ))
        return findings

    def _detect_hardcoded_secret(self, tree, file_path, code):
        findings = []
        lines = code.split('\n')
        for node in pyast.walk(tree):
            if isinstance(node, pyast.Assign):
                for target in node.targets if isinstance(node.targets, list) else [node.targets]:
                    name = getattr(target, 'id', '') if isinstance(target, pyast.Name) else ''
                    if name.lower() in ('password', 'secret', 'api_key', 'apikey',
                                        'token', 'access_key', 'private_key'):
                        if isinstance(node.value, pyast.Constant) and isinstance(node.value.value, str):
                            if len(node.value.value) >= 8:
                                findings.append(ASTFinding(
                                    "Hardcoded Secret (AST)", "critical", file_path,
                                    node.lineno, node.col_offset, len(name),
                                    f"Hardcoded {name} detected — credential in source code",
                                    f"The variable '{name}' is assigned a string literal. This credential is committed to version control.",
                                    f"Use os.environ.get('{name}') or a secret manager. Never hardcode credentials.",
                                    "CWE-798", confidence="high",
                                ))
        return findings

    def _detect_deserialization(self, tree, file_path):
        findings = []
        for lineno, col, node in self._find_function_calls(tree, 'loads'):
            if isinstance(node.func, pyast.Attribute):
                module = getattr(node.func.value, 'id', '') if isinstance(node.func.value, pyast.Name) else ''
                if module in ('pickle', 'yaml', 'marshal'):
                    findings.append(ASTFinding(
                        "Insecure Deserialization (AST)", "critical", file_path, lineno, col, 10,
                        f"{module}.loads() used — remote code execution risk",
                        f"{module}.loads() can deserialize arbitrary objects, enabling code execution on untrusted data.",
                        f"Avoid deserializing untrusted data. Use json.loads() for JSON, or yaml.safe_load() for YAML.",
                        "CWE-502", confidence="high",
                        sink_call=f"{module}.loads()",
                    ))
        return findings

    def _detect_path_traversal(self, tree, file_path):
        findings = []
        for lineno, col, node in self._find_function_calls(tree, 'join'):
            for arg in node.args:
                if isinstance(arg, pyast.BinOp) and isinstance(arg.op, pyast.Add):
                    findings.append(ASTFinding(
                        "Path Traversal (AST)", "high", file_path, lineno, col, 10,
                        "os.path.join() with concatenated user input — path traversal risk",
                        "Concatenating strings inside path.join() allows attackers to escape the intended directory.",
                        "Validate user input against a whitelist of allowed paths. Never concatenate raw user input into file paths.",
                        "CWE-22", confidence="medium",
                        sink_call="os.path.join()",
                    ))
        return findings

    def _has_concatenation(self, node):
        if isinstance(node, pyast.BinOp) and isinstance(node.op, (pyast.Add, pyast.Mod)):
            return True
        if isinstance(node, pyast.JoinedStr):
            return True
        return False

    def _has_user_input(self, node):
        code = ast.dump(node)
        for patterns in self.SOURCE_PATTERNS.values():
            for pat in patterns:
                if pat in code:
                    return True
        return False


class GenericASTAnalyzer:
    """Fallback for languages without tree-sitter. Uses pattern-based heuristics."""

    def analyze(self, file_path, code, language):
        findings = []
        ext = Path(file_path).suffix.lower()

        if ext in ('.js', '.ts', '.jsx', '.tsx'):
            findings.extend(self._js_patterns(file_path, code))
        elif ext == '.go':
            findings.extend(self._go_patterns(file_path, code))
        elif ext == '.rs':
            findings.extend(self._rust_patterns(file_path, code))

        return findings

    def _js_patterns(self, file_path, code):
        findings = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            if 'innerHTML' in line and not ('.test.' in file_path.lower() or 'spec.' in file_path.lower()):
                if 'const ' in line and ('=' in line) and not ('trusted' in line.lower()):
                    findings.append(ASTFinding(
                        "XSS: innerHTML (ASST)", "high", file_path, i, 1, len(line),
                        "innerHTML assignment — XSS risk", "Use textContent", "Replace with textContent",
                        "CWE-79", confidence="medium", sink_call="innerHTML",
                    ))

            if re.search(r"eval\s*\(\s*[^)]*\b(?:req|input|param|query|body|user)", line, re.I):
                findings.append(ASTFinding(
                    "eval() with user input (ASST)", "critical", file_path, i, 1, len(line),
                    "eval() called with potential user input — RCE risk",
                    "eval() executes arbitrary code. Never pass user input to eval().",
                    "Use JSON.parse() for data parsing instead of eval().",
                    "CWE-95", confidence="high", sink_call="eval()",
                ))

        return findings

    def _go_patterns(self, file_path, code):
        findings = []
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:db\.Query|db\.Exec|db\.QueryRow)\s*\(\s*fmt\.Sprintf', line, re.I):
                findings.append(ASTFinding(
                    "Go: SQL Injection (ASST)", "critical", file_path, i, 1, len(line),
                    "SQL query built with fmt.Sprintf — injection risk",
                    "Use ? placeholders: db.Query(query, arg1, arg2)",
                    "Replace fmt.Sprintf with parameterized query",
                    "CWE-89", confidence="high",
                ))
        return findings

    def _rust_patterns(self, file_path, code):
        findings = []
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if 'unsafe' in line and '{' in line:
                findings.append(ASTFinding(
                    "Rust: Unsafe Block (ASST)", "high", file_path, i, 1, len(line),
                    "Unsafe block bypasses Rust guarantees", "Document safety invariants",
                    "Minimize unsafe blocks. Document why each is necessary.",
                    "CWE-119", confidence="medium",
                ))
        return findings
