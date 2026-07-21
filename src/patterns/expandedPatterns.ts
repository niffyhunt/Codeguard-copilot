/**
 * CodeGuard Copilot — Expanded vulnerability patterns.
 * Phase D: 40+ patterns covering Go, Rust, C++, C#, Ruby.
 * Generated from Raven learning pipeline + manual security research.
 */
import { SecurityPattern as _SecurityPattern } from '../patterns/vulnerabilityPatterns';

export interface SecurityPattern {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    regex: RegExp;
    languages: string[];
    message: string;
    explanation: string;
    fix: string;
    codeExample?: string;
    cwe?: string;
}

export const expandedPatterns: SecurityPattern[] = [

    // ═══════════════ GO PATTERNS ═══════════════

    {
        type: 'Go: SQL Injection (database/sql)',
        severity: 'critical',
        regex: /(?:db\.Query|db\.Exec|db\.QueryRow)\s*\(\s*["'][^"']*%[sdv]/gi,
        languages: ['go'],
        message: 'SQL query uses string formatting with user input — SQL injection risk',
        explanation: 'database/sql queries built with fmt.Sprintf and user input can lead to SQL injection. Use parameterized queries with ? placeholders.',
        fix: 'Use db.Query("SELECT * FROM users WHERE id = ?", userInput) instead of string formatting.',
        codeExample: 'rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)',
        cwe: 'CWE-89',
    },
    {
        type: 'Go: Insecure Random (math/rand)',
        severity: 'high',
        regex: /(?:math\/rand\.(?:Int|Float|Read|Perm|Shuffle)|rand\.(?:Int|Float))/g,
        languages: ['go'],
        message: 'math/rand is not cryptographically secure — use crypto/rand for security-sensitive operations',
        explanation: 'math/rand uses a deterministic PRNG. For tokens, session IDs, or cryptographic operations, use crypto/rand.',
        fix: 'Replace with crypto/rand.Reader for security-sensitive random generation.',
        codeExample: 'import "crypto/rand"\nfunc generateToken() (string, error) {\n    b := make([]byte, 32)\n    _, err := rand.Read(b)\n    return hex.EncodeToString(b), err\n}',
        cwe: 'CWE-338',
    },
    {
        type: 'Go: Hardcoded Secret',
        severity: 'critical',
        regex: /(?:password|secret|token|key)\s*[:=]\s*"[^"]{8,}"/gi,
        languages: ['go'],
        message: 'Hardcoded credential detected in Go source',
        explanation: 'Credentials in source code are exposed in version control. Use environment variables or a secret manager.',
        fix: 'Replace with os.Getenv("SECRET_KEY") or a secret management solution.',
        codeExample: 'secretKey := os.Getenv("SECRET_KEY")',
        cwe: 'CWE-798',
    },
    {
        type: 'Go: Unescaped HTML Template',
        severity: 'high',
        regex: /template\.HTML|template\.JS|template\.CSS|Unsafe\(/g,
        languages: ['go'],
        message: 'Using unescaped template types — possible XSS',
        explanation: 'template.HTML, template.JS, and template.CSS bypass auto-escaping in html/template, enabling XSS if user input reaches them.',
        fix: 'Avoid using these types unless absolutely necessary. Validate and sanitize HTML content before wrapping.',
        codeExample: '// Safe: html/template auto-escapes by default\ntmpl.Execute(w, userInput)',
        cwe: 'CWE-79',
    },

    // ═══════════════ RUST PATTERNS ═══════════════

    {
        type: 'Rust: Unsafe Block',
        severity: 'high',
        regex: /unsafe\s*\{/g,
        languages: ['rust'],
        message: 'Unsafe block detected — bypasses Rust safety guarantees',
        explanation: 'Unsafe blocks disable Rust\'s memory safety checks. They should be minimized and carefully documented.',
        fix: 'Consider if the operation can be performed safely. If unsafe is necessary, document the safety invariants.',
        codeExample: '// SAFETY: This is safe because the pointer is valid for reads',
        cwe: 'CWE-119',
    },
    {
        type: 'Rust: Hardcoded Secret',
        severity: 'critical',
        regex: /(?:password|secret|token|api_key|apikey)\s*[:=]\s*"[^"]{8,}"/gi,
        languages: ['rust'],
        message: 'Hardcoded credential in Rust — use env vars',
        explanation: 'Credentials embedded in source code are committed to version control. Use std::env::var.',
        fix: 'let secret = std::env::var("SECRET_KEY").expect("SECRET_KEY not set");',
        codeExample: 'let secret = std::env::var("SECRET_KEY")?;',
        cwe: 'CWE-798',
    },
    {
        type: 'Rust: Use of eval/exec',
        severity: 'critical',
        regex: /Command::new|std::process::Command|\.output\(\)|\.spawn\(\)/g,
        languages: ['rust'],
        message: 'System command execution — potential command injection if input is user-controlled',
        explanation: 'std::process::Command can execute arbitrary system commands. If arguments come from user input, command injection is possible.',
        fix: 'Validate and sanitize all inputs passed to Command::arg(). Prefer dedicated libraries over shell execution.',
        codeExample: 'let output = Command::new("ls").arg(sanitized_path).output()?;',
        cwe: 'CWE-78',
    },
    {
        type: 'Rust: Weak Crypto (MD5/SHA1)',
        severity: 'high',
        regex: /md5::|Md5::|sha1::|Sha1::|MD5|SHA1/g,
        languages: ['rust'],
        message: 'MD5 or SHA1 usage detected — use SHA-256 or stronger',
        explanation: 'MD5 and SHA1 are cryptographically broken. Use SHA-256 or SHA-512 for security-sensitive hashing.',
        fix: 'Replace with sha2::Sha256 or sha2::Sha512 from the sha2 crate.',
        codeExample: 'use sha2::{Sha256, Digest};\nlet hash = Sha256::digest(data);',
        cwe: 'CWE-327',
    },

    // ═══════════════ C++ PATTERNS ═══════════════

    {
        type: 'C++: Buffer Overflow (strcpy/sprintf/gets)',
        severity: 'critical',
        regex: /\b(?:strcpy|strcat|sprintf|gets|scanf|sscanf)\s*\(/g,
        languages: ['cpp', 'c'],
        message: 'Unsafe C function — buffer overflow risk',
        explanation: 'strcpy, strcat, sprintf, and gets do not perform bounds checking. Use safe alternatives like strncpy, snprintf, or C++ std::string.',
        fix: 'Replace with strncpy, snprintf, or C++ std::string with bounds checking.',
        codeExample: 'std::string dest = src; // Safe C++ alternative',
        cwe: 'CWE-120',
    },
    {
        type: 'C++: Memory Leak (new without delete)',
        severity: 'medium',
        regex: /\bnew\s+\w+/g,
        languages: ['cpp'],
        message: 'Manual memory allocation — prefer smart pointers',
        explanation: 'Raw new without corresponding delete causes memory leaks. Use std::unique_ptr or std::shared_ptr.',
        fix: 'Replace with std::make_unique<T>(args) or std::make_shared<T>(args).',
        codeExample: 'auto ptr = std::make_unique<MyClass>(args);',
        cwe: 'CWE-401',
    },
    {
        type: 'C++: SQL Injection',
        severity: 'critical',
        regex: /(?:sprintf|snprintf|format|<<)\s*.*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s/gi,
        languages: ['cpp'],
        message: 'SQL query built with string formatting — SQL injection risk',
        explanation: 'SQL queries constructed with string formatting and user input enable SQL injection. Use parameterized queries.',
        fix: 'Use prepared statements with parameter binding.',
        codeExample: 'stmt.prepare("SELECT * FROM users WHERE id = ?");\nstmt.bind(1, user_id);',
        cwe: 'CWE-89',
    },

    // ═══════════════ C# PATTERNS ═══════════════

    {
        type: 'C#: SQL Injection (string concatenation)',
        severity: 'critical',
        regex: /(?:SqlCommand|OleDbCommand|OdbcCommand)\s*\(\s*["'][^"']*\+|\.Format\s*\(\s*["'][^"']*SELECT/gi,
        languages: ['csharp'],
        message: 'SQL command built with string concatenation — SQL injection',
        explanation: 'Concatenating user input into SQL strings enables SQL injection. Use parameterized queries with SqlParameter.',
        fix: 'Use SqlParameter for all user-supplied values in SQL queries.',
        codeExample: 'var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);\ncmd.Parameters.AddWithValue("@id", userId);',
        cwe: 'CWE-89',
    },
    {
        type: 'C#: Hardcoded Connection String',
        severity: 'critical',
        regex: /(?:ConnectionString|connString|connStr)\s*=\s*"[^"]*(?:password|pwd|uid|user id)[^"]*"/gi,
        languages: ['csharp'],
        message: 'Database credentials hardcoded in connection string',
        explanation: 'Connection strings containing credentials in source code are exposed to version control. Use appsettings.json with Secret Manager in development.',
        fix: 'Store connection strings in appsettings.json with User Secrets for development or Azure Key Vault / environment variables for production.',
        codeExample: 'var connString = Configuration.GetConnectionString("DefaultConnection");',
        cwe: 'CWE-798',
    },
    {
        type: 'C#: Insecure Deserialization',
        severity: 'high',
        regex: /(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\s*\./g,
        languages: ['csharp'],
        message: 'Insecure deserialization — remote code execution risk',
        explanation: 'BinaryFormatter and similar serializers can deserialize arbitrary types, leading to RCE. Use safe alternatives.',
        fix: 'Replace with System.Text.Json for JSON serialization or implement a SerializationBinder for type validation.',
        codeExample: 'var obj = JsonSerializer.Deserialize<MyType>(json);',
        cwe: 'CWE-502',
    },

    // ═══════════════ RUBY PATTERNS ═══════════════

    {
        type: 'Ruby: SQL Injection (ActiveRecord)',
        severity: 'critical',
        regex: /(?:where|find_by|order|select|having)\s*\(\s*["'][^"']*#\{/gi,
        languages: ['ruby'],
        message: 'ActiveRecord query with string interpolation — SQL injection',
        explanation: 'Using string interpolation (#{}) in ActiveRecord queries enables SQL injection. Use parameterized queries.',
        fix: 'Use array conditions or named placeholders: where("email = ?", email).',
        codeExample: 'User.where("email = ?", params[:email])',
        cwe: 'CWE-89',
    },
    {
        type: 'Ruby: Command Injection (system/exec/backticks)',
        severity: 'critical',
        regex: /(?:system|exec|spawn|`)\s*\(?\s*["'][^"']*#\{/gi,
        languages: ['ruby'],
        message: 'Shell command with string interpolation — command injection',
        explanation: 'Passing unsanitized user input to system(), exec(), or backtick commands enables command injection.',
        fix: 'Use system("cmd", arg1, arg2) with separate arguments instead of string interpolation.',
        codeExample: 'system("ls", "-l", sanitized_path)',
        cwe: 'CWE-78',
    },
    {
        type: 'Ruby: Mass Assignment',
        severity: 'high',
        regex: /\.(?:update|create|new|assign_attributes)\s*\(\s*params\[/gi,
        languages: ['ruby'],
        message: 'Potential mass assignment vulnerability — use strong parameters',
        explanation: 'Passing raw params to update/create enables mass assignment attacks. Use strong parameters to whitelist allowed fields.',
        fix: 'Use params.require(:model).permit(:field1, :field2) to whitelist attributes.',
        codeExample: 'def user_params\n  params.require(:user).permit(:name, :email)\nend',
        cwe: 'CWE-915',
    },
    {
        type: 'Ruby: Unsafe Deserialization (YAML/Marshal)',
        severity: 'high',
        regex: /YAML\.(?:load|unsafe_load)|Marshal\.(?:load|restore)/g,
        languages: ['ruby'],
        message: 'Unsafe deserialization — YAML.load and Marshal.load can execute arbitrary code',
        explanation: 'YAML.load (without safe_load) and Marshal.load can instantiate arbitrary objects. Use YAML.safe_load or avoid deserializing untrusted data.',
        fix: 'Replace YAML.load with YAML.safe_load. Avoid Marshal.load on untrusted data.',
        codeExample: 'data = YAML.safe_load(untrusted_yaml, permitted_classes: [Date])',
        cwe: 'CWE-502',
    },
];
