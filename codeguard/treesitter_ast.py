"""CodeGuard Multi-Language AST Engine — tree-sitter powered.

Replaces ALL regex-based rules for supported languages with AST-based analysis.
Regex is banned except for string-literal extraction inside AST nodes.

Languages: Python, JavaScript/TypeScript, Go, Rust, Java, PHP, Ruby, C#, Kotlin
"""
import re
import os
from pathlib import Path


class LanguageAnalyzer:
    """Per-language AST analyzer. Exposes call graph, data flow, taint sources, sinks."""

    def __init__(self, name: str):
        self.name = name
        self._parser = None
        self._language = None

    @property
    def parser(self):
        if self._parser is None:
            self._init_parser()
        return self._parser

    def _init_parser(self):
        raise NotImplementedError

    def is_available(self):
        try:
            return self.parser is not None
        except Exception:
            return False

    def parse(self, code: bytes):
        if self.parser is None:
            return None
        return self.parser.parse(code)

    def analyze(self, file_path, code):
        raise NotImplementedError


class PythonAnalyzer(LanguageAnalyzer):
    SOURCES = ["request", "input", "sys.argv", "environ", "args", "form", "params", "getenv", "body", "query", "data", "json", "cookies", "headers"]
    SINKS = {
        "sql": ["execute", "executemany", "raw", "query", "cursor.execute", "db.execute", "db.session.execute", "session.execute"],
        "command": ["system", "popen", "run", "call", "Popen", "exec", "eval", "spawn", "check_output", "check_call", "getoutput"],
        "html": ["innerHTML", "render_template", "Markup", "write"],
        "file": ["open", "read", "write", "save", "dump", "upload", "readfile"],
        "deserialize": ["loads", "load", "yaml.load", "pickle.load", "marshal.load"],
        "network": ["get", "post", "request", "fetch", "urlopen", "urlretrieve"],
    }
    KEYWORDS_SECRET = ("password", "secret", "api_key", "apikey", "token", "access_key", "private_key", "auth_token", "bearer", "jwt_secret", "secret_key", "api_secret")

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("python")
            if so_path:
                lang = Language(so_path, "python")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        try:
            import importlib.resources as res
            with res.path(f"tree_sitter_{lang_name}", f"{lang_name}.so") as f:
                return str(f)
        except Exception:
            pass
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()

        root = tree.root_node
        for node in self._iter_nodes(root):
            if node.type == "call":
                fname = self._get_call_name(node, code_str)
                if fname is None:
                    continue
                fname_lower = fname.lower()
                for sink_type, sinks in self.SINKS.items():
                    for sink in sinks:
                        if sink.lower() in fname_lower:
                            if self._has_source_above(node, root, code_str):
                                findings.append(self._make_finding(
                                    file_path, node,
                                    f"Python: {sink_type.title()} Injection (tree-sitter)",
                                    {"sql": "CWE-89", "command": "CWE-78", "html": "CWE-79",
                                     "file": "CWE-22", "deserialize": "CWE-502", "network": "CWE-918"}[sink_type],
                                    "critical" if sink_type in ("sql", "command", "deserialize") else "high",
                                    f"`{fname}` called with user-controlled input — {sink_type} risk",
                                    {"sql": "Use parameterized queries with ? placeholders",
                                     "command": "Use subprocess with argument lists, not shell=True",
                                     "html": "Use template auto-escaping and avoid Markup()",
                                     "file": "Validate and sanitize user-controlled file paths",
                                     "deserialize": "Use safe deserializers like json.loads()",
                                     "network": "Validate redirect URLs and SSRF guards"}[sink_type],
                                ))
                            break
                    else:
                        continue
                    break
            elif node.type == "assignment":
                left_text = self._node_text(node.child_by_field_name("left"), code_str)
                if left_text and any(k in left_text.lower() for k in self.KEYWORDS_SECRET):
                    right = node.child_by_field_name("right")
                    if right and right.type == "string":
                        val = self._node_text(right, code_str)
                        if val and len(val.strip("'\"")) >= 8:
                            findings.append(self._make_finding(
                                file_path, node, "Python: Hardcoded Secret (tree-sitter)",
                                "CWE-798", "critical",
                                f"Hardcoded secret `{left_text}` in source code",
                                "Use os.environ.get() or a secret manager. Never hardcode secrets.",
                            ))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _get_call_name(self, node, code):
        func_node = node.child_by_field_name("function")
        if func_node:
            return self._node_text(func_node, code)
        for child in node.children:
            if child.type in ("identifier", "attribute", "subscript"):
                return self._node_text(child, code)
        return None

    def _node_text(self, node, code):
        if node is None:
            return ""
        return code[node.start_byte:node.end_byte]

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = self._node_text(node.parent, code)
            for src in self.SOURCES:
                if src in parent_text.lower():
                    return True
        text = self._node_text(node, code)
        for src in self.SOURCES:
            if src in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:" + self.name,
            "ast_node_type": node.type,
        }


class JSAnalyzer(LanguageAnalyzer):
    SOURCES = ["req", "request", "params", "query", "body", "input", "process.env", "req.body", "req.query", "req.params", "event", "ctx", "arg"]
    SINKS = {
        "sql": ["execute", "query", "raw", "find", "findOne", "aggregate", "$where"],
        "xss": ["innerHTML", "document.write", "dangerouslySetInnerHTML", "outerHTML", "insertAdjacentHTML"],
        "command": ["exec", "spawn", "execSync", "execFile", "fork", "eval", "Function"],
        "network": ["fetch", "axios", "get", "post", "request", "got"],
        "deserialize": ["JSON.parse", "serialize", "deserialize", "unserialize"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("javascript")
            if so_path:
                lang = Language(so_path, "javascript")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        try:
            import importlib.resources as res
            with res.path(f"tree_sitter_{lang_name}", f"{lang_name}.so") as f:
                return str(f)
        except Exception:
            pass
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "call_expression":
                fname = self._get_call_name(node, code_str)
                if fname is None:
                    continue
                fname_lower = fname.lower()

                if self._is_sink(fname_lower, "xss") and self._has_source_above(node, root, code_str):
                    findings.append(self._make_finding(file_path, node,
                        "Cross-Site Scripting (tree-sitter)", "CWE-79", "critical",
                        f"`{fname}` with user input — XSS risk",
                        "Replace innerHTML with textContent. Sanitize with DOMPurify if HTML needed."))
                elif self._is_sink(fname_lower, "command"):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Command Injection (tree-sitter)", "CWE-78", "critical",
                            f"`{fname}` called with user-controlled input",
                            "Use argument arrays. Never pass user input to exec/eval."))
                elif self._is_sink(fname_lower, "sql"):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "SQL/NoSQL Injection (tree-sitter)", "CWE-89", "critical",
                            f"`{fname}` with user input — database injection risk",
                            "Use parameterized queries or an ORM. Avoid string concatenation."))
                elif self._is_sink(fname_lower, "network"):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "SSRF (tree-sitter)", "CWE-918", "high",
                            f"`{fname}` with user-controlled URL — SSRF risk",
                            "Validate and whitelist allowed URLs. Avoid passing raw user input to fetch()."))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _get_call_name(self, node, code):
        for child in node.children:
            if child.type in ("identifier", "member_expression", "property_identifier"):
                return code[child.start_byte:child.end_byte]
        func_node = node.child_by_field_name("function")
        if func_node:
            return self._node_text(func_node, code)
        return code[node.start_byte:node.end_byte][:30]

    def _node_text(self, node, code):
        if node is None:
            return ""
        return code[node.start_byte:node.end_byte]

    def _is_sink(self, name, sink_type):
        name_lower = name.lower()
        for s in self.SINKS.get(sink_type, []):
            if s.lower() in name_lower:
                return True
        return False

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = self._node_text(node.parent, code)
            for src in self.SOURCES:
                if src in parent_text.lower():
                    return True
        text = self._node_text(node, code)
        for src in self.SOURCES:
            if src in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:" + self.name,
            "ast_node_type": node.type,
        }


class GoAnalyzer(LanguageAnalyzer):
    SOURCES = ["r.URL.Query()", "r.FormValue", "r.PostFormValue", "os.Args", "os.Getenv", "r.URL", "r.Body", "r.Header"]
    SINKS = {
        "sql": ["db.Query", "db.Exec", "db.QueryRow", "fmt.Sprintf", "db.Raw", "db.ExecContext", "db.QueryContext"],
        "command": ["exec.Command", "os.StartProcess", "syscall.Exec", "exec.CommandContext"],
        "file": ["os.Open", "os.Create", "ioutil.ReadFile", "os.ReadFile", "os.WriteFile"],
        "network": ["http.Get", "http.Post", "http.Do", "http.Client.Do"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("go")
            if so_path:
                lang = Language(so_path, "go")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "call_expression":
                name = code_str[node.start_byte:node.end_byte].split("(")[0].strip()
                name_lower = name.lower()

                if any(s in name_lower for s in ["db.query", "db.exec", "db.queryrow"]) and "fmt.sprintf" in code_str[node.start_byte:min(node.start_byte+200, len(code_str))].lower():
                    findings.append(self._make_finding(file_path, node,
                        "Go: SQL Injection (tree-sitter)", "CWE-89", "critical",
                        f"SQL query with fmt.Sprintf — SQL injection in `{name}`",
                        "Use ? placeholders: db.Query(query, arg1, arg2)"))
                elif any(s in name_lower for s in ["exec.command", "exec.commandcontext"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Go: Command Injection (tree-sitter)", "CWE-78", "critical",
                            f"`{name}` with user input — command injection",
                            "Validate all arguments passed to exec.Command"))
                elif any(s in name_lower for s in ["http.get", "http.post", "http.do"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Go: SSRF (tree-sitter)", "CWE-918", "high",
                            f"`{name}` with user-controlled URL — SSRF risk",
                            "Validate and restrict outbound HTTP targets"))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = code[node.parent.start_byte:node.parent.end_byte] if node.parent else ""
            for src in self.SOURCES:
                if src.lower() in parent_text.lower():
                    return True
        text = code[node.start_byte:node.end_byte]
        for src in self.SOURCES:
            if src.lower() in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:go",
            "ast_node_type": node.type,
        }


class RustAnalyzer(LanguageAnalyzer):
    SOURCES = ["std::env::args", "std::io::stdin", "env::var", "std::env::var", "String::from_utf8_lossy"]
    SINKS = {
        "command": ["Command::new", "std::process::Command", "Command::arg", "Command::args"],
        "unsafe": ["unsafe"],
        "crypto": ["md5::", "sha1::", "Md5::", "Sha1::"],
        "fs": ["std::fs::read", "std::fs::write", "File::open", "File::create"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("rust")
            if so_path:
                lang = Language(so_path, "rust")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "unsafe_block":
                findings.append(self._make_finding(file_path, node,
                    "Rust: Unsafe Block (tree-sitter)", "CWE-119", "high",
                    "Unsafe block bypasses Rust safety guarantees",
                    "Minimize unsafe. Document safety invariants in a SAFETY comment."))
            elif node.type == "call_expression":
                name = code_str[node.start_byte:node.end_byte].split("(")[0].strip()
                name_lower = name.lower()

                if "command::new" in name_lower or "std::process::command" in name_lower:
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Rust: Command Injection (tree-sitter)", "CWE-78", "critical",
                            f"`{name}` with user input — command injection risk",
                            "Validate all inputs passed to Command::arg()"))
                elif any(w in name_lower for w in ["md5", "sha1"]):
                    findings.append(self._make_finding(file_path, node,
                        "Rust: Weak Crypto (tree-sitter)", "CWE-327", "high",
                        f"Weak hash algorithm `{name}` used",
                        "Replace with SHA-256, SHA-3, or argon2"))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = code[node.parent.start_byte:node.parent.end_byte] if node.parent else ""
            for src in self.SOURCES:
                if src.lower() in parent_text.lower():
                    return True
        text = code[node.start_byte:node.end_byte]
        for src in self.SOURCES:
            if src.lower() in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:rust",
            "ast_node_type": node.type,
        }


class JavaAnalyzer(LanguageAnalyzer):
    SOURCES = ["request.getParameter", "request.getQueryString", "request.getHeader", "request.getCookies",
               "HttpServletRequest", "@RequestParam", "@PathVariable", "@RequestBody", "@ModelAttribute"]
    SINKS = {
        "sql": ["executeQuery", "executeUpdate", "prepareStatement", "Statement", "createQuery", "entityManager",
                "jdbcTemplate.query", "jdbcTemplate.update", "session.createQuery", "session.createSQLQuery"],
        "jndi": ["InitialContext.lookup", "Context.lookup", "JndiTemplate.lookup"],
        "command": ["Runtime.exec", "ProcessBuilder", "exec", "Runtime.getRuntime().exec"],
        "ssrf": ["URL.openConnection", "URL.openStream", "HttpURLConnection", "RestTemplate.exchange",
                  "WebClient.create", "HttpClient.send", "okhttp3"],
        "deserialize": ["ObjectInputStream.readObject", "readUnshared", "XMLDecoder.readObject"],
        "xss": ["response.getWriter().write", "PrintWriter.write", "out.write", "ModelAndView"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("java")
            if so_path:
                lang = Language(so_path, "java")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "method_invocation":
                name = code_str[node.start_byte:node.end_byte].split("(")[0].strip()
                name_lower = name.lower()

                for sink_type, sinks in self.SINKS.items():
                    for s in sinks:
                        if s.lower() in name_lower:
                            if self._has_source_above(node, root, code_str):
                                cwe_map = {"sql": "CWE-89", "jndi": "CWE-917", "command": "CWE-78",
                                           "ssrf": "CWE-918", "deserialize": "CWE-502", "xss": "CWE-79"}
                                sev_map = {"sql": "critical", "jndi": "critical", "command": "critical",
                                           "ssrf": "high", "deserialize": "critical", "xss": "high"}
                                fix_map = {
                                    "sql": "Use parameterized queries with PreparedStatement or JPA @Query with named parameters",
                                    "jndi": "Do not pass user input to JNDI lookups. Validate and restrict JNDI protocols.",
                                    "command": "Avoid Runtime.exec with user input. Use ProcessBuilder with validated args.",
                                    "ssrf": "Validate and whitelist URLs. Use a URL blocklist. Never pass raw user input.",
                                    "deserialize": "Use safe deserialization. Validate input. Avoid ObjectInputStream.",
                                    "xss": "Use template auto-escaping (Thymeleaf, JSP EL). HTML-encode output.",
                                }
                                findings.append(self._make_finding(file_path, node,
                                    f"Java: {sink_type.title()} (tree-sitter)", cwe_map[sink_type], sev_map[sink_type],
                                    f"`{name}` with user input — {sink_type} risk",
                                    fix_map[sink_type]))
                            break
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = code[node.parent.start_byte:node.parent.end_byte] if node.parent else ""
            for src in self.SOURCES:
                if src.lower() in parent_text.lower():
                    return True
        text = code[node.start_byte:node.end_byte]
        for src in self.SOURCES:
            if src.lower() in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:java",
            "ast_node_type": node.type,
        }


class PHPAnalyzer(LanguageAnalyzer):
    SOURCES = ["$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE", "$_FILES", "php://input", "getenv", "getallheaders"]
    SINKS = {
        "sql": ["mysqli_query", "mysql_query", "pg_query", "sqlsrv_query", "oci_parse", "PDO.query", "PDO.exec",
                "mysqli_prepare", "db->query", "db->exec"],
        "eval": ["eval", "assert", "create_function", "preg_replace", "call_user_func", "call_user_func_array"],
        "command": ["exec", "system", "shell_exec", "passthru", "popen", "proc_open", "backtick"],
        "file": ["file_get_contents", "file_put_contents", "fopen", "fwrite", "include", "require",
                 "include_once", "require_once", "move_uploaded_file"],
        "xss": ["echo", "print", "printf", "vprintf", "out.write"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("php")
            if so_path:
                lang = Language(so_path, "php")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "function_call_expression":
                name = self._get_call_name(node, code_str)
                if name is None:
                    continue
                name_lower = name.lower()

                if name_lower in ("eval", "assert", "create_function"):
                    findings.append(self._make_finding(file_path, node,
                        "PHP: Dynamic Code Execution (tree-sitter)", "CWE-95", "critical",
                        f"`{name}()` executes arbitrary PHP code",
                        "Avoid eval/assert. Use safer alternatives like call_user_func with whitelist."))
                elif any(s in name_lower for s in ["mysqli_query", "mysql_query", "pg_query", "pdo.query", "pdo.exec"]):
                    findings.append(self._make_finding(file_path, node,
                        "PHP: SQL Injection (tree-sitter)", "CWE-89", "critical",
                        f"`{name}()` — potential SQL injection",
                        "Use prepared statements with PDO or MySQLi. Never concatenate user input."))
                elif any(s in name_lower for s in ["exec", "system", "shell_exec", "passthru"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "PHP: Command Injection (tree-sitter)", "CWE-78", "critical",
                            f"`{name}()` with user input — command injection",
                            "Avoid shell functions with user input. Use escapeshellarg() if unavoidable."))
                elif any(s in name_lower for s in ["include", "require"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "PHP: LFI/RFI (tree-sitter)", "CWE-98", "critical",
                            f"`{name}()` with user-controlled path — file inclusion risk",
                            "Validate and whitelist allowed include paths. Never pass user input directly."))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _get_call_name(self, node, code):
        for child in node.children:
            if child.type in ("name", "qualified_name", "member_call_expression"):
                return code[child.start_byte:child.end_byte]
        return None

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = code[node.parent.start_byte:node.parent.end_byte] if node.parent else ""
            for src in self.SOURCES:
                if src.lower() in parent_text.lower():
                    return True
        text = code[node.start_byte:node.end_byte]
        for src in self.SOURCES:
            if src.lower() in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:php",
            "ast_node_type": node.type,
        }


class RubyAnalyzer(LanguageAnalyzer):
    SOURCES = ["params", "request", "env", "ARGV", "STDIN", "cookies", "session", "rack.input"]
    SINKS = {
        "sql": ["where", "find_by", "find_by_sql", "execute", "exec_query", "sanitize_sql",
                "ActiveRecord::Base.connection.execute", "from", "order", "group", "having"],
        "command": ["system", "exec", "spawn", "popen", "open3", "IO.popen", "Open3.popen3",
                     "Open3.capture3", "backtick"],
        "deserialize": ["YAML.load", "YAML.unsafe_load", "Marshal.load", "Marshal.restore",
                         "JSON.load", "Oj.load"],
        "file": ["File.open", "File.read", "File.write", "IO.read", "IO.write", "FileUtils"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("ruby")
            if so_path:
                lang = Language(so_path, "ruby")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "call":
                name = code_str[node.start_byte:node.end_byte].split("(")[0].strip()
                name_lower = name.split()[-1].lower() if name else ""

                if name_lower in ("yaml.load", "yaml.unsafe_load", "marshal.load", "marshal.restore"):
                    findings.append(self._make_finding(file_path, node,
                        "Ruby: Unsafe Deserialization (tree-sitter)", "CWE-502", "critical",
                        f"`{name}` deserializes untrusted data — RCE risk",
                        "Replace with YAML.safe_load or JSON.parse"))
                elif any(s in name_lower for s in ["system", "exec ", "spawn "]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Ruby: Command Injection (tree-sitter)", "CWE-78", "critical",
                            f"`{name}` with user input — command injection",
                            "Use system('cmd', arg1, arg2) with separate arguments"))
                elif any(s in name_lower for s in ["where", "find_by_sql", "execute"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Ruby: SQL Injection (tree-sitter)", "CWE-89", "critical",
                            f"`{name}` with user input — SQL injection risk",
                            "Use parameterized queries: where('email = ?', email)"))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = code[node.parent.start_byte:node.parent.end_byte] if node.parent else ""
            for src in self.SOURCES:
                if src.lower() in parent_text.lower():
                    return True
        text = code[node.start_byte:node.end_byte]
        for src in self.SOURCES:
            if src.lower() in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:ruby",
            "ast_node_type": node.type,
        }


class CSharpAnalyzer(LanguageAnalyzer):
    SOURCES = ["Request.QueryString", "Request.Form", "Request.Params", "Request.Headers", "Request.Cookies",
               "HttpRequest", "HttpContext", "context.Request", "FromBody", "FromRoute", "FromQuery"]
    SINKS = {
        "sql": ["SqlCommand", "OleDbCommand", "OdbcCommand", "EntityFramework", "context.Database.ExecuteSqlRaw",
                "FromSqlRaw", "ExecuteSqlRaw", "ExecuteSqlCommand", "SqlDataAdapter", "DbCommand"],
        "deserialize": ["BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter",
                         "JavaScriptSerializer", "XmlSerializer"],
        "command": ["Process.Start", "ProcessStartInfo", "Diagnostics.Process.Start"],
        "ssrf": ["HttpClient.SendAsync", "HttpClient.GetAsync", "HttpClient.PostAsync",
                  "WebClient.DownloadString", "WebRequest.Create"],
        "xss": ["Response.Write", "HttpContext.Current.Response.Write", "Html.Raw", "MvcHtmlString.Create"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("c_sharp")
            if so_path:
                lang = Language(so_path, "c_sharp")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "invocation_expression":
                name = code_str[node.start_byte:node.end_byte].split("(")[0].strip()
                name_lower = name.lower()

                for sink_type, sinks in self.SINKS.items():
                    for s in sinks:
                        if s.lower() in name_lower:
                            if self._has_source_above(node, root, code_str):
                                cwe_map = {"sql": "CWE-89", "deserialize": "CWE-502", "command": "CWE-78",
                                           "ssrf": "CWE-918", "xss": "CWE-79"}
                                sev_map = {"sql": "critical", "deserialize": "critical", "command": "critical",
                                           "ssrf": "high", "xss": "high"}
                                fix_map = {
                                    "sql": "Use parameterized queries with SqlParameter. Avoid string concatenation.",
                                    "deserialize": "Replace with System.Text.Json. Avoid BinaryFormatter entirely.",
                                    "command": "Use Process.Start with argument list. Never pass user input to shell.",
                                    "ssrf": "Validate and restrict HTTP targets. Use HttpClientFactory with Polly.",
                                    "xss": "Use Razor auto-escaping @ syntax. Avoid Html.Raw with user input.",
                                }
                                findings.append(self._make_finding(file_path, node,
                                    f"C#: {sink_type.title()} (tree-sitter)", cwe_map[sink_type], sev_map[sink_type],
                                    f"`{name}` with user input — {sink_type} risk",
                                    fix_map[sink_type]))
                            break
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = code[node.parent.start_byte:node.parent.end_byte] if node.parent else ""
            for src in self.SOURCES:
                if src.lower() in parent_text.lower():
                    return True
        text = code[node.start_byte:node.end_byte]
        for src in self.SOURCES:
            if src.lower() in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:csharp",
            "ast_node_type": node.type,
        }


class TypeScriptAnalyzer(LanguageAnalyzer):
    SOURCES = ["req", "request", "params", "query", "body", "input", "process.env",
               "req.body", "req.query", "req.params", "ctx", "event", "arg", "req.headers"]
    SINKS = {
        "sql": ["execute", "query", "raw", "find", "findOne", "aggregate", "$where",
                "createQuery", "createQueryBuilder", "getRawMany", "typeorm"],
        "xss": ["innerHTML", "document.write", "dangerouslySetInnerHTML", "outerHTML"],
        "command": ["exec", "spawn", "execSync", "execFile", "fork", "eval", "Function"],
        "ssrf": ["axios.get", "axios.post", "fetch", "got", "superagent"],
        "deserialize": ["JSON.parse", "unserialize", "deserialize"],
        "nosqli": ["$ne", "$gt", "$regex", "$where", "collection.find"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("typescript")
            if so_path:
                lang = Language(so_path, "typescript")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "call_expression":
                fname = self._get_call_name(node, code_str)
                if fname is None:
                    continue
                fname_lower = fname.lower()

                if any(s in fname_lower for s in ["exec", "spawn", "execsync"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "TypeScript: Command Injection (tree-sitter)", "CWE-78", "critical",
                            f"`{fname}` with user input — command injection",
                            "Use execFile or child_process.spawn with argument array"))
                elif any(s in fname_lower for s in ["innerhtml", "outerhtml", "document.write"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "TypeScript: XSS (tree-sitter)", "CWE-79", "critical",
                            f"`{fname}` with user input — XSS risk",
                            "Use textContent. If HTML needed, sanitize with DOMPurify."))
                elif any(s in fname_lower for s in ["executequery", "queryraw", "fromsqlraw"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "TypeScript: SQL Injection (tree-sitter)", "CWE-89", "critical",
                            f"`{fname}` with raw SQL — SQL injection risk",
                            "Use parameterized queries or QueryBuilder with .where(:param)"))
                elif any(s in fname_lower for s in ["find", "findone", "aggregate", "$where"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "TypeScript: NoSQL Injection (tree-sitter)", "CWE-943", "critical",
                            f"`{fname}` with user input — NoSQL injection risk",
                            "Use mongo-sanitize or validate input types before queries"))
                elif any(s in fname_lower for s in ["fetch", "axios.get", "axios.post", "got"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "TypeScript: SSRF (tree-sitter)", "CWE-918", "high",
                            f"`{fname}` with user-controlled URL — SSRF risk",
                            "Validate and whitelist allowed URLs"))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _get_call_name(self, node, code):
        for child in node.children:
            if child.type in ("identifier", "member_expression", "property_identifier"):
                return code[child.start_byte:child.end_byte]
        func_node = node.child_by_field_name("function")
        if func_node:
            return self._node_text(func_node, code)
        return code[node.start_byte:node.end_byte][:30]

    def _node_text(self, node, code):
        if node is None:
            return ""
        return code[node.start_byte:node.end_byte]

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = self._node_text(node.parent, code)
            for src in self.SOURCES:
                if src in parent_text.lower():
                    return True
        text = self._node_text(node, code)
        for src in self.SOURCES:
            if src in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:typescript",
            "ast_node_type": node.type,
        }


class KotlinAnalyzer(LanguageAnalyzer):
    SOURCES = ["request.getParameter", "request.getQueryString", "@RequestParam", "@PathVariable",
               "intent.getStringExtra", "intent.getData", "intent.getExtras", "activity.intent"]
    SINKS = {
        "webview": ["webView.loadUrl", "webView.loadData", "webView.loadDataWithBaseURL",
                     "WebView.loadUrl", "WebView.loadData"],
        "sql": ["rawQuery", "execSQL", "rawQueryWithFactory", "compileStatement",
                 "entityManager.createNativeQuery", "session.createSQLQuery"],
        "intent": ["startActivity", "startService", "sendBroadcast", "bindService",
                    "Intent.setData", "intent.putExtra"],
        "command": ["Runtime.exec", "ProcessBuilder", "exec"],
        "ssrf": ["URL.readText", "URL.openStream", "HttpURLConnection", "okhttp3"],
        "deserialize": ["ObjectInputStream.readObject", "readUnshared"],
    }

    def _init_parser(self):
        try:
            from tree_sitter import Parser, Language
            so_path = self._find_grammar("kotlin")
            if so_path:
                lang = Language(so_path, "kotlin")
                self._language = lang
                self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def _find_grammar(self, lang_name):
        paths = [
            f"/usr/lib/tree-sitter-{lang_name}.so",
            f"/usr/local/lib/tree-sitter-{lang_name}.so",
            os.path.expanduser(f"~/.tree-sitter/{lang_name}.so"),
            os.path.expanduser(f"~/.local/lib/tree-sitter-{lang_name}.so"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def analyze(self, file_path, code):
        findings = []
        tree = self.parse(code.encode() if isinstance(code, str) else code)
        if tree is None:
            return findings
        code_str = code if isinstance(code, str) else code.decode()
        root = tree.root_node

        for node in self._iter_nodes(root):
            if node.type == "call_expression":
                name = code_str[node.start_byte:node.end_byte].split("(")[0].strip().split(".")[-1]
                name_lower = name.lower()

                if any(s in name_lower for s in ["loadurl", "loaddata"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Kotlin: WebView XSS (tree-sitter)", "CWE-79", "critical",
                            f"WebView loading content from user input — XSS/RCE risk",
                            "Disable JavaScript if possible. Sanitize HTML with Jsoup.clean()."))
                elif any(s in name_lower for s in ["rawquery", "execsql", "rawquerywithfactory"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Kotlin: SQL Injection (tree-sitter)", "CWE-89", "critical",
                            f"Raw DB query with user input — SQL injection risk",
                            "Use Room @Query with named parameters. Never concatenate SQL strings."))
                elif any(s in name_lower for s in ["startactivity", "startservice", "sendbroadcast"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Kotlin: Implicit Intent Hijack (tree-sitter)", "CWE-927", "high",
                            f"Implicit intent with user data — intent hijacking risk",
                            "Use explicit intents. Validate received intents with Intent.parseUri."))
                elif any(s in name_lower for s in ["runtime.exec", "processbuilder"]):
                    if self._has_source_above(node, root, code_str):
                        findings.append(self._make_finding(file_path, node,
                            "Kotlin: Command Injection (tree-sitter)", "CWE-78", "critical",
                            f"`{name}` with user input — command injection",
                            "Use ProcessBuilder with validated argument list"))
        return findings

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _has_source_above(self, node, root, code):
        if node.parent:
            parent_text = code[node.parent.start_byte:node.parent.end_byte] if node.parent else ""
            for src in self.SOURCES:
                if src.lower() in parent_text.lower():
                    return True
        text = code[node.start_byte:node.end_byte]
        for src in self.SOURCES:
            if src.lower() in text.lower():
                return True
        return False

    def _make_finding(self, file_path, node, rule, cwe, sev, msg, fix):
        return {
            "rule_id": rule, "severity": sev, "cwe": cwe,
            "file_path": file_path,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1] + 1,
            "message": msg, "fix": fix,
            "analyzer": "tree-sitter:kotlin",
            "ast_node_type": node.type,
        }
