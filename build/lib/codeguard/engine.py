"""CodeGuard — Security analysis engine. Reads shared pattern definitions and scans source code.

One engine, multiple workflows: CLI, pre-commit, CI/CD, IDE integration.
All without duplicating scanning logic.
"""
import json
import re
import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).parent
PATTERNS_PATH = PACKAGE_DIR / "patterns.json"


class Finding:
    def __init__(self, rule_id, severity, file_path, line, column, length,
                 message, explanation, fix, cwe=None, confidence="high",
                 source=None, sink=None, dataflow_path=None, analyzer="regex"):
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
        self.source = source
        self.sink = sink
        self.dataflow_path = dataflow_path
        self.analyzer = analyzer

    def to_dict(self):
        from .intelligence import generate_intelligent_explanation as _explain
        explanation = _explain({
            "rule_id": self.rule_id, "severity": self.severity, "cwe": self.cwe,
            "file_path": self.file_path, "line": self.line,
            "analyzer": self.analyzer, "source": self.source, "sink": self.sink,
            "fix": self.fix, "confidence": self.confidence,
        })
        return {
            "rule_id": self.rule_id, "severity": self.severity,
            "file_path": self.file_path, "line": self.line,
            "column": self.column, "length": self.length,
            "message": self.message, "explanation": explanation,
            "fix": self.fix, "cwe": self.cwe, "confidence": self.confidence,
            "source": self.source, "sink": self.sink,
            "dataflow_path": self.dataflow_path, "analyzer": self.analyzer,
            "intelligence": {
                "method": "deterministic",
                "source": "embedded_cwe_knowledge",
                "requires_api": False,
            }
        }


class CodeGuardEngine:
    def __init__(self, patterns_path=None):
        self.patterns_path = patterns_path or PATTERNS_PATH
        self.patterns = []
        self.custom_patterns = []
        self._load_patterns()
        self._ast_enabled = True

    def _is_test_or_generated(self, file_path):
        path = file_path.lower().replace('\\', '/')
        fname = os.path.basename(path)
        if fname.startswith('test_') or fname.startswith('conftest.'):
            return True
        if '_test.' in fname or '.test.' in fname or 'spec_' in fname:
            return True
        if '/tests/' in path or '/test/' in path or '/__pycache__/' in path:
            return True
        if '/fixtures/' in path or '/examples/' in path or '/docs/' in path:
            return True
        if '/vendor/' in path or '/node_modules/' in path:
            return True
        return False

    def _load_patterns(self):
        if os.path.exists(self.patterns_path):
            with open(self.patterns_path) as f:
                data = json.load(f)
                self.patterns = data.get("patterns", [])
                for p in self.patterns:
                    if isinstance(p.get("regex"), str):
                        p["_compiled"] = re.compile(p["regex"], re.IGNORECASE | re.MULTILINE)

    def load_custom_patterns(self, custom_path):
        if os.path.exists(custom_path):
            with open(custom_path) as f:
                data = json.load(f)
                custom = data.get("customPatterns", [])
                for p in custom:
                    if isinstance(p.get("regex"), str):
                        p["_compiled"] = re.compile(p["regex"], re.IGNORECASE | re.MULTILINE)
                self.custom_patterns = custom
                return len(custom)
        return 0

    def _resolve_language(self, file_path):
        ext = Path(file_path).suffix.lower()
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
            ".jsx": "javascript", ".java": "java", ".php": "php", ".go": "go",
            ".rs": "rust", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "c",
            ".cs": "csharp", ".rb": "ruby", ".swift": "swift", ".kt": "kotlin",
        }
        return ext_map.get(ext, ext.lstrip("."))

    def scan_file(self, file_path, severity_filter=None):
        if not os.path.exists(file_path):
            return []

        language = self._resolve_language(file_path)
        is_test = self._is_test_or_generated(file_path)

        try:
            with open(file_path, "r", errors="ignore") as f:
                lines = f.readlines()
                code = "".join(lines)
        except Exception:
            return []

        findings = []
        all_patterns = self.patterns + self.custom_patterns

        # Layer 1: Regex (fast first pass — skip for test files)
        if not is_test:
            for pattern in all_patterns:
                if severity_filter and pattern.get("severity") not in severity_filter:
                    continue

                langs = pattern.get("languages", ["*"])
                if "*" not in langs and language not in langs:
                    continue

                regex = pattern.get("_compiled")
                if not regex:
                    try:
                        regex = re.compile(pattern["regex"], re.IGNORECASE | re.MULTILINE)
                        pattern["_compiled"] = regex
                    except re.error:
                        continue

                for line_num, line_text in enumerate(lines, 1):
                    for match in regex.finditer(line_text):
                        findings.append(Finding(
                            rule_id=pattern.get("type", "unknown"),
                            severity=pattern.get("severity", "medium"),
                            file_path=file_path, line=line_num,
                            column=match.start() + 1,
                            length=match.end() - match.start(),
                            message=pattern.get("message", ""),
                            explanation=pattern.get("explanation", ""),
                            fix=pattern.get("fix", ""),
                            cwe=pattern.get("cwe"),
                            confidence="high" if not is_test else "low",
                            analyzer="regex",
                        ))

        # Layer 2: AST analysis (context-aware — all files, test context flagged)
        if self._ast_enabled and language == "python":
            try:
                from .ast_analyzer import PythonASTAnalyzer
                ast_findings = PythonASTAnalyzer().analyze(file_path, code)
                for af in ast_findings:
                    confidence = af.confidence
                    if is_test:
                        confidence = "low"
                        af.message = f"[TEST FILE] {af.message}"
                    findings.append(Finding(
                        rule_id=af.rule_id, severity=af.severity,
                        file_path=file_path, line=af.line, column=af.column,
                        length=af.length, message=af.message,
                        explanation=af.explanation, fix=af.fix, cwe=af.cwe,
                        confidence=confidence,
                        source=af.source_call, sink=af.sink_call,
                        dataflow_path=af.dataflow_path, analyzer="ast",
                    ))
            except ImportError:
                pass
            except Exception:
                pass

        if language in ("javascript", "typescript", "go", "rust"):
            try:
                from .ast_analyzer import GenericASTAnalyzer
                ast_findings = GenericASTAnalyzer().analyze(file_path, code, language)
                for af in ast_findings:
                    confidence = af.confidence
                    if is_test:
                        confidence = "low"
                    findings.append(Finding(
                        rule_id=af.rule_id, severity=af.severity,
                        file_path=file_path, line=af.line, column=af.column,
                        length=af.length, message=af.message,
                        explanation=af.explanation, fix=af.fix, cwe=af.cwe,
                        confidence=confidence,
                        source=af.source_call, sink=af.sink_call, analyzer="ast",
                    ))
            except ImportError:
                pass
            except Exception:
                pass

        return self._deduplicate(findings)

    def scan_directory(self, dir_path, severity_filter=None, exclude_patterns=None):
        if exclude_patterns is None:
            exclude_patterns = [".git", "node_modules", "__pycache__", "venv", ".venv",
                               "dist", "build", ".next", "out", "target", "vendor", "egg-info"]

        findings = []
        ext_set = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".php", ".go",
                    ".rs", ".cpp", ".c", ".cc", ".cs", ".rb", ".swift", ".kt"}

        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in exclude_patterns and not d.startswith(".")]
            for fname in files:
                if Path(fname).suffix.lower() in ext_set:
                    file_path = os.path.join(root, fname)
                    findings.extend(self.scan_file(file_path, severity_filter))

        return sorted(findings, key=lambda f: self._severity_order(f.severity))

    def _deduplicate(self, findings):
        seen = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _severity_order(self, sev):
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 9)

    def get_patterns(self):
        return self.patterns[:]

    def get_pattern_count(self):
        return len(self.patterns) + len(self.custom_patterns)

    def get_supported_languages(self):
        langs = set()
        for p in self.patterns + self.custom_patterns:
            langs.update(p.get("languages", ["*"]))
        langs.discard("*")
        return sorted(langs)

    def get_stats(self):
        return {
            "patterns_loaded": len(self.patterns),
            "custom_patterns": len(self.custom_patterns),
            "languages": self.get_supported_languages(),
            "patterns_path": str(self.patterns_path),
        }
