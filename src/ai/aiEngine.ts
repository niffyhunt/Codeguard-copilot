import { Vulnerability } from '../patterns/securityScanner';
import * as vscode from 'vscode';

export class AISecurityEngine {
    private apiKey: string;
    private provider: 'anthropic' | 'groq' | 'openai';
    private apiEndpoint: string;

    constructor() {
        const config = vscode.workspace.getConfiguration('codeguard');
        this.provider = config.get<'anthropic' | 'groq' | 'openai'>('aiProvider', 'anthropic');
        this.apiKey = config.get<string>('apiKey', process.env.ANTHROPIC_API_KEY || '') || '';
        this.apiEndpoint = this.getApiEndpoint();
    }

    private getApiEndpoint(): string {
        switch (this.provider) {
            case 'anthropic':
                return 'https://api.anthropic.com/v1/messages';
            case 'groq':
                return 'https://api.groq.com/openai/v1/chat/completions';
            case 'openai':
                return 'https://api.openai.com/v1/chat/completions';
            default:
                return 'https://api.anthropic.com/v1/messages';
        }
    }

    async analyzeCode(
        code: string,
        language: string,
        existingVulns: Vulnerability[]
    ): Promise<Vulnerability[]> {
        if (!this.apiKey) {
            console.warn('No API key configured. Skipping AI analysis.');
            return [];
        }

        if (code.split('\n').length > 1000) {
            console.log('File too large for AI analysis');
            return [];
        }

        const prompt = this.buildSecurityPrompt(code, language, existingVulns);

        try {
            const response = await this.callAI(prompt);
            return this.parseAIResponse(response, code);
        } catch (error) {
            console.error('AI analysis failed:', error);
            return [];
        }
    }

    private buildSecurityPrompt(
        code: string,
        language: string,
        existingVulns: Vulnerability[]
    ): string {
        const vulnTypes = existingVulns.map(v => v.type).join(', ');

        return `You are a security expert analyzing ${language} code for vulnerabilities.

${existingVulns.length > 0 ? `Pattern-based scanner already found: ${vulnTypes}\n` : ''}

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

Perform deep security analysis and identify:

1. Vulnerabilities missed by pattern matching (logic flaws, race conditions, business logic issues)
1. Context-aware issues (authentication bypasses, authorization flaws)
1. Framework-specific security anti-patterns
1. Subtle injection vulnerabilities
1. Cryptographic misuse
1. Session management issues

For EACH vulnerability, provide:

- type: Name of vulnerability
- severity: "critical", "high", "medium", or "low"
- line: Line number (0-indexed) where issue occurs
- explanation: Clear explanation of why this is a security risk
- fix: Specific remediation advice
- codeExample: Working code example showing the secure version
- cwe: CWE identifier (e.g., "CWE-89")

IMPORTANT: Return ONLY a valid JSON array, no other text. Format:
[{
"type": "vulnerability name",
"severity": "critical",
"line": 5,
"explanation": "detailed risk explanation",
"fix": "how to fix this",
"codeExample": "secure code example",
"cwe": "CWE-XXX"
}]

If no additional vulnerabilities found, return: []`;
    }

    private async callAI(prompt: string): Promise<string> {
        switch (this.provider) {
            case 'anthropic':
                return await this.callClaude(prompt);
            case 'groq':
                return await this.callGroq(prompt);
            case 'openai':
                return await this.callOpenAI(prompt);
            default:
                throw new Error(`Unsupported AI provider: ${this.provider}`);
        }
    }

    private async callClaude(prompt: string): Promise<string> {
        const response = await fetch(this.apiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.apiKey,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 4000,
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ]
            })
        });

        if (!response.ok) {
            throw new Error(`Claude API error: ${response.statusText}`);
        }

        const data = await response.json();
        return (data as any).content?.[0]?.text || '';
    }

    private async callGroq(prompt: string): Promise<string> {
        const response = await fetch(this.apiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${this.apiKey}`
            },
            body: JSON.stringify({
                model: 'mixtral-8x7b-32768',
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.1
            })
        });

        if (!response.ok) {
            throw new Error(`Groq API error: ${response.statusText}`);
        }

        const data = await response.json();
        return (data as any).choices?.[0]?.message?.content || '';
    }

    private async callOpenAI(prompt: string): Promise<string> {
        const response = await fetch(this.apiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${this.apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4',
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.1
            })
        });

        if (!response.ok) {
            throw new Error(`OpenAI API error: ${response.statusText}`);
        }

        const data = await response.json();
        return (data as any).choices?.[0]?.message?.content || '';
    }

    private parseAIResponse(response: string, code: string): Vulnerability[] {
        try {
            let jsonText = response;

            const jsonMatch = response.match(/\[\s*\{[\s\S]*\}\s*\]/);
            if (jsonMatch) {
                jsonText = jsonMatch[0];
            }

            const vulnerabilities = JSON.parse(jsonText);

            if (!Array.isArray(vulnerabilities)) {
                console.error('AI response is not an array');
                return [];
            }

            const lines = code.split('\n');

            return vulnerabilities.map((v: any) => ({
                type: v.type || 'Unknown Vulnerability',
                severity: this.normalizeSeverity(v.severity),
                line: Math.min(v.line || 0, lines.length - 1),
                column: 0,
                length: 100,
                message: v.type || 'Security issue detected',
                explanation: v.explanation || 'No explanation provided',
                fix: v.fix || 'Review this code for security issues',
                codeExample: v.codeExample,
                cwe: v.cwe
            }));
        } catch (error) {
            console.error('Failed to parse AI response:', error);
            console.log('Raw response:', response);
            return [];
        }
    }

    private normalizeSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
        const normalized = (severity || 'medium').toLowerCase();
        if (['critical', 'high', 'medium', 'low'].includes(normalized)) {
            return normalized as 'critical' | 'high' | 'medium' | 'low';
        }
        return 'medium';
    }

    async testConnection(): Promise<boolean> {
        try {
            const testPrompt = 'Respond with only: {"status": "ok"}';
            const response = await this.callAI(testPrompt);
            return response.includes('ok');
        } catch (error) {
            console.error('AI connection test failed:', error);
            return false;
        }
    }
}