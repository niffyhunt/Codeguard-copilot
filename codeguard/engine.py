"""CodeGuard — Security analysis engine. Reads shared pattern definitions and scans source code.

One engine, multiple workflows: CLI, pre-commit, CI/CD, IDE integration.
All without duplicating scanning logic.
"""
import json
import re
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

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
        if self._ast_enabled:
            ast_findings = self._run_ast_analysis(language, file_path, code, is_test, lines)
            findings.extend(ast_findings)

        # Layer 2.5: Secret detection v2 (entropy + structure + context)
        if not is_test:
            try:
                from .secret_detection import scan_file as secret_scan
                secret_findings = secret_scan(file_path, code, output_format="finding")
                findings.extend(secret_findings)
            except ImportError:
                pass
            except Exception:
                pass

        # Layer 3: WraithCore enrichment (optional)
        if findings:
            try:
                from .wraithcore import get_wraithcore
                wc = get_wraithcore()
                if wc.is_ready():
                    findings = self._enrich_with_wraithcore(findings, code, language, file_path)
            except ImportError:
                pass
            except Exception:
                pass

        return self._deduplicate(findings)

    def _enrich_with_wraithcore(self, findings, code, language, file_path):
        from .wraithcore import get_wraithcore
        wc = get_wraithcore()
        for f in findings:
            cwe = f.cwe or ""
            rule = f.rule_id or ""
            if "CVE" in rule or "CWE" in rule or any(kw in rule.lower() for kw in ["cve", "kev", "exploit"]):
                try:
                    result = wc.score_cve(rule, f.message[:300], f.fix)
                    if result.get("exploited_in_wild"):
                        f.severity = "critical"
                        f.message = f"[WRAITHCORE] {f.message}"
                        f.confidence = "high"
                except Exception:
                    pass
            if f.severity in ("critical", "high") and any(kw in rule.lower() for kw in ["command", "rce", "deserial"]):
                try:
                    session = {"src_ip": "unknown", "duration": 0, "commands": [f.message], "downloads": []}
                    result = wc.classify_attacker(session)
                    if result.get("attacker_class") in ("interactive_attacker", "ransomware_dropper"):
                        f.severity = "critical"
                        f.confidence = "high"
                except Exception:
                    pass
            if "phish" in rule.lower() or "xss" in rule.lower():
                try:
                    result = wc.detect_phishing(f.message)
                    if result.get("is_phishing") and result.get("confidence", 0) > 0.8:
                        f.severity = "critical"
                        f.confidence = "high"
                except Exception:
                    pass
        return findings

    def _run_ast_analysis(self, language, file_path, code, is_test, lines):
        findings = []
        code_str = code if isinstance(code, str) else code.decode()

        if language == "python":
            try:
                from .ast_analyzer import PythonASTAnalyzer
                ast_findings = PythonASTAnalyzer().analyze(file_path, code)
                for af in ast_findings:
                    confidence = af.confidence
                    if is_test:
                        confidence = "low"
                        af.message = f"[TEST FILE] {af.message}"
                    findings.append(self._ast_to_finding(af, file_path, confidence))
            except ImportError:
                pass
            except Exception:
                pass

        ts_lang_map = {
            "python": "PythonAnalyzer",
            "javascript": "JSAnalyzer",
            "typescript": "TypeScriptAnalyzer",
            "go": "GoAnalyzer",
            "rust": "RustAnalyzer",
            "java": "JavaAnalyzer",
            "php": "PHPAnalyzer",
            "ruby": "RubyAnalyzer",
            "csharp": "CSharpAnalyzer",
            "kotlin": "KotlinAnalyzer",
        }

        if language in ts_lang_map:
            try:
                from .treesitter_ast import (PythonAnalyzer, JSAnalyzer, GoAnalyzer,
                                              RustAnalyzer, JavaAnalyzer, PHPAnalyzer,
                                              RubyAnalyzer, CSharpAnalyzer,
                                              TypeScriptAnalyzer, KotlinAnalyzer,
                                              LanguageAnalyzer)
                analyzer_class = eval(ts_lang_map[language])
                analyzer = analyzer_class()
                if analyzer.is_available():
                    ts_results = analyzer.analyze(file_path, code_str)
                    for r in ts_results:
                        confidence = "medium"
                        if is_test:
                            confidence = "low"
                        findings.append(Finding(
                            rule_id=r["rule_id"], severity=r["severity"],
                            file_path=file_path, line=r["line"],
                            column=r["column"], length=r.get("length", 10),
                            message=r["message"], explanation=r.get("fix", ""),
                            fix=r.get("fix", ""), cwe=r.get("cwe"),
                            confidence=confidence,
                            source=r.get("source_call"), sink=r.get("sink_call"),
                            analyzer="tree-sitter",
                        ))
            except ImportError:
                pass
            except Exception:
                pass

        try:
            from .ast_analyzer import GenericASTAnalyzer
            gen_findings = GenericASTAnalyzer().analyze(file_path, code_str, language)
            for af in gen_findings:
                confidence = af.confidence
                if is_test:
                    confidence = "low"
                findings.append(self._ast_to_finding(af, file_path, confidence))
        except ImportError:
            pass
        except Exception:
            pass

        return findings

    def _ast_to_finding(self, af, file_path, confidence):
        return Finding(
            rule_id=af.rule_id, severity=af.severity,
            file_path=file_path, line=af.line, column=af.column,
            length=af.length, message=af.message,
            explanation=af.explanation, fix=af.fix, cwe=af.cwe,
            confidence=confidence,
            source=af.source_call if hasattr(af, 'source_call') else None,
            sink=af.sink_call if hasattr(af, 'sink_call') else None,
            dataflow_path=af.dataflow_path if hasattr(af, 'dataflow_path') else None,
            analyzer="ast",
        )

    def scan_directory(self, dir_path, severity_filter=None, exclude_patterns=None, exploitability=False):
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

        sorted_findings = sorted(findings, key=lambda f: self._severity_order(f.severity))

        if exploitability and sorted_findings:
            try:
                from .exploitability import summarize
                scores_input = []
                for f in sorted_findings:
                    line_text = ""
                    try:
                        with open(f.file_path) as fp:
                            line_text = fp.read().split("\n")[f.line - 1] if f.line else ""
                    except Exception:
                        pass
                    scores_input.append((f, line_text))
                stats = summarize(scores_input)
                return sorted_findings, stats
            except ImportError:
                pass
            except Exception:
                pass

        return sorted_findings

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
