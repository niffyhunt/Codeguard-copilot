import { AISecurityEngine } from '../ai/aiEngine';
import { vulnerabilityPatterns, SecurityPattern } from './vulnerabilityPatterns';

export interface Vulnerability {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    line: number;
    column: number;
    length: number;
    message: string;
    explanation: string;
    fix: string;
    codeExample?: string;
    cwe?: string;
}

export class SecurityScanner {
    private patterns: SecurityPattern[];
    private aiEngine: AISecurityEngine;

    constructor(aiEngine: AISecurityEngine) {
        this.aiEngine = aiEngine;
        this.patterns = vulnerabilityPatterns;
    }

    async scan(code: string, language: string): Promise<Vulnerability[]> {
        const vulnerabilities: Vulnerability[] = [];

        // Phase 1: Fast pattern-based detection
        const patternVulns = this.patternScan(code, language);
        vulnerabilities.push(...patternVulns);

        // Phase 2: AI-enhanced deep analysis (if enabled and warranted)
        if (this.shouldRunAIAnalysis(code, patternVulns)) {
            try {
                const aiVulns = await this.aiEngine.analyzeCode(code, language, patternVulns);
                vulnerabilities.push(...aiVulns);
            } catch (error) {
                console.error('AI analysis failed:', error);
            }
        }

        return this.deduplicateAndPrioritize(vulnerabilities);
    }

    private patternScan(code: string, language: string): Vulnerability[] {
        const vulnerabilities: Vulnerability[] = [];
        const lines = code.split('\n');

        // Filter patterns for this language
        const applicablePatterns = this.patterns.filter(
            p => p.languages.includes(language) || p.languages.includes('*')
        );

        // Scan each line with each pattern
        applicablePatterns.forEach(pattern => {
            lines.forEach((line, lineIndex) => {
                const matches = [...line.matchAll(pattern.regex)];

                matches.forEach(match => {
                    if (match.index !== undefined) {
                        vulnerabilities.push({
                            type: pattern.type,
                            severity: pattern.severity,
                            line: lineIndex,
                            column: match.index,
                            length: match[0].length,
                            message: pattern.message,
                            explanation: pattern.explanation,
                            fix: pattern.fix,
                            codeExample: pattern.codeExample,
                            cwe: pattern.cwe
                        });
                    }
                });
            });
        });

        return vulnerabilities;
    }

    private shouldRunAIAnalysis(code: string, patternVulns: Vulnerability[]): boolean {
        const vscode = require('vscode');
        const config = vscode.workspace.getConfiguration('codeguard');
        const aiEnabled = config.get('enableAI', true);

        if (!aiEnabled) return false;

        // Complex patterns that trigger AI scan
        const complexPatterns = [
            /crypto|encrypt|decrypt|hash/i,
            /jwt|token|session|auth/i,
            /password|secret|api[_-]?key|credential/i,
            /eval|exec|system|shell|command/i,
            /serialize|pickle|yaml\.load/i,
            /xml|xpath|ldap/i
        ];

        const hasComplexPattern = complexPatterns.some(pattern => pattern.test(code));
        const hasCriticalVuln = patternVulns.some(v => v.severity === 'critical');

        return hasComplexPattern || hasCriticalVuln || patternVulns.length > 3;
    }

    private deduplicateAndPrioritize(vulns: Vulnerability[]): Vulnerability[] {
        const unique = Array.from(
            new Map(
                vulns.map(v => [`${v.line}-${v.column}-${v.type}`, v])
            ).values()
        );

        const severityOrder: Record<string, number> = {
            critical: 0,
            high: 1,
            medium: 2,
            low: 3
        };

        return unique.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    }

    // Public method to add custom patterns
    public addCustomPattern(pattern: SecurityPattern): void {
        this.patterns.push(pattern);
    }

    // Public method to get all patterns
    public getPatterns(): SecurityPattern[] {
        return [...this.patterns];
    }
}