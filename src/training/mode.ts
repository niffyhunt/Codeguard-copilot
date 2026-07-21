/**
 * CodeGuard Copilot Security Training Mode.
 * Interactive security education for developers.
 * Shows WHY a vulnerability matters, not just THAT it exists.
 */
import * as vscode from 'vscode';

export interface TrainingModule {
    id: string;
    title: string;
    description: string;
    cwe: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    vulnerableCode: string;
    secureCode: string;
    explanation: string;
    realWorldExample: string;
    quiz?: {
        question: string;
        options: string[];
        correctIndex: number;
    };
}

const TRAINING_MODULES: TrainingModule[] = [
    {
        id: 'sql-injection',
        title: 'SQL Injection: The 20-Year-Old Vulnerability',
        description: 'Learn how SQL injection works, how attackers exploit it, and how to prevent it.',
        cwe: 'CWE-89',
        severity: 'critical',
        vulnerableCode: `// VULNERABLE - String concatenation with user input
const query = "SELECT * FROM users WHERE email = '" + userEmail + "'";
db.execute(query);`,
        secureCode: `// SECURE - Parameterized query
const query = "SELECT * FROM users WHERE email = ?";
db.execute(query, [userEmail]);`,
        explanation: 'SQL injection allows attackers to execute arbitrary SQL commands by injecting malicious code through user input. Parameterized queries separate code from data, preventing injection.',
        realWorldExample: 'In 2023, the MOVEit Transfer SQL injection vulnerability (CVE-2023-34362) affected thousands of organizations worldwide.',
        quiz: {
            question: 'Which approach prevents SQL injection?',
            options: [
                'String concatenation with user input',
                'Using regex to filter special characters',
                'Parameterized queries with bound parameters',
                'Encoding output before display'
            ],
            correctIndex: 2,
        },
    },
    {
        id: 'hardcoded-secrets',
        title: 'Your Secrets Are Showing',
        description: 'Why hardcoding credentials is dangerous and how to handle secrets properly.',
        cwe: 'CWE-798',
        severity: 'critical',
        vulnerableCode: `// VULNERABLE - Hardcoded API key
const API_KEY = "sk-abc123def456ghi789";
fetch("https://api.example.com/data", {
    headers: { Authorization: \`Bearer \${API_KEY}\` }
});`,
        secureCode: `// SECURE - Environment variable
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error("API_KEY not configured");
fetch("https://api.example.com/data", {
    headers: { Authorization: \`Bearer \${API_KEY}\` }
});`,
        explanation: 'Secrets in source code are exposed in version control, accessible to anyone with repository access. Use environment variables or secret management services.',
        realWorldExample: 'GitHub scans over 200 token types and notified thousands of developers about leaked credentials in 2025 alone.',
        quiz: {
            question: 'Where should API keys be stored?',
            options: [
                'In source code comments',
                'In a config file committed to git',
                'In environment variables or a secret manager',
                'In the database'
            ],
            correctIndex: 2,
        },
    },
    {
        id: 'xss',
        title: 'Cross-Site Scripting: Beyond Alert(1)',
        description: 'Understanding XSS beyond the basic alert box and how to prevent it.',
        cwe: 'CWE-79',
        severity: 'high',
        vulnerableCode: `// VULNERABLE - Direct innerHTML injection
element.innerHTML = userComment;`,
        secureCode: `// SECURE - Escaped text content
element.textContent = userComment;
// OR use a sanitization library
element.innerHTML = DOMPurify.sanitize(userComment);`,
        explanation: 'XSS allows attackers to inject malicious scripts into web pages viewed by others. These scripts can steal cookies, tokens, and sensitive data.',
        realWorldExample: 'British Airways was fined £20M in 2020 after an XSS attack on their payment page compromised 380,000 customer records.',
        quiz: {
            question: 'What should you use instead of innerHTML for user content?',
            options: [
                'outerHTML',
                'textContent or a sanitizer like DOMPurify',
                'innerText with inline styles',
                'document.write()'
            ],
            correctIndex: 1,
        },
    },
];

export class SecurityTrainingMode {
    private currentModule: number = 0;

    getModules(): TrainingModule[] {
        return TRAINING_MODULES;
    }

    getModule(id: string): TrainingModule | undefined {
        return TRAINING_MODULES.find(m => m.id === id);
    }

    getModuleCount(): number {
        return TRAINING_MODULES.length;
    }

    startTraining(): TrainingModule[] {
        return TRAINING_MODULES;
    }

    getModuleHTML(module: TrainingModule): string {
        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { padding: 20px; font-family: var(--vscode-font-family); color: var(--vscode-editor-foreground); }
        .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .critical { background: #e74c3c; color: white; }
        .high { background: #e67e22; color: white; }
        .code-block { background: var(--vscode-textCodeBlock-background); padding: 12px; border-radius: 4px; margin: 8px 0; font-family: monospace; }
        .vulnerable { border-left: 3px solid #e74c3c; }
        .secure { border-left: 3px solid #27ae60; }
        .quiz { margin-top: 16px; padding: 12px; background: var(--vscode-input-background); border-radius: 4px; }
        .quiz button { margin: 4px; padding: 6px 12px; cursor: pointer; }
    </style>
</head>
<body>
    <h1>${module.title}</h1>
    <span class="severity-badge ${module.severity}">${module.severity.toUpperCase()}</span>
    <span style="margin-left: 8px; font-size: 12px;">${module.cwe}</span>

    <p>${module.description}</p>

    <h3>Vulnerable Code</h3>
    <pre class="code-block vulnerable"><code>${this.escapeHtml(module.vulnerableCode)}</code></pre>

    <h3>Secure Code</h3>
    <pre class="code-block secure"><code>${this.escapeHtml(module.secureCode)}</code></pre>

    <h3>Explanation</h3>
    <p>${module.explanation}</p>

    <h3>Real-World Example</h3>
    <p>${module.realWorldExample}</p>

    ${module.quiz ? this.getQuizHTML(module) : ''}
</body>
</html>`;
    }

    private getQuizHTML(module: TrainingModule): string {
        if (!module.quiz) return '';
        return `<div class="quiz">
            <h4>Quiz: ${module.quiz.question}</h4>
            ${module.quiz.options.map((opt, i) =>
                `<button onclick="checkAnswer(${i}, ${module.quiz!.correctIndex})">${opt}</button>`
            ).join('')}
            <p id="quiz-result" style="margin-top: 8px;"></p>
            <script>
                function checkAnswer(selected, correct) {
                    document.getElementById('quiz-result').textContent =
                        selected === correct ? 'Correct!' : 'Try again';
                    document.getElementById('quiz-result').style.color =
                        selected === correct ? '#27ae60' : '#e74c3c';
                }
            </script>
        </div>`;
    }

    private escapeHtml(text: string): string {
        return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
}
