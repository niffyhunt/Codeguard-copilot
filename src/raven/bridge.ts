/**
 * Raven → CodeGuard Intelligence Bridge.
 * Receives attacker behavior intelligence from Raven (cowrie honeypot data)
 * and proposes new CodeGuard detection patterns.
 *
 * Workflow:
 *   Raven attacker behavior → behavior normalization → candidate pattern
 *   → confidence scoring → human review → CodeGuard rule proposal
 *   → test generation → rule publication
 */
import { SecurityPattern } from '../patterns/vulnerabilityPatterns';

export interface RavenIntelligenceEvent {
    eventType: string;
    cwe?: string;
    attackStage?: string;
    threatScore?: number;
    commands?: string[];
    iocs?: string[];
    matchedTactics?: string[];
    timestamp: string;
    source?: string;
}

export interface CandidatePattern {
    proposedType: string;
    proposedRegex: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    languages: string[];
    confidence: number;
    evidenceUrl?: string;
    attackerBehavior: string;
    cwe?: string;
}

export class RavenIntelligenceBridge {
    private candidatePatterns: CandidatePattern[] = [];

    /**
     * Ingest Raven intelligence event and generate candidate detection patterns.
     * Called by the telemetry pipeline when new attacker behavior is observed.
     */
    ingestEvent(event: RavenIntelligenceEvent): CandidatePattern | null {
        if (!event.commands || event.commands.length === 0) return null;
        if (!event.cwe && !event.matchedTactics) return null;

        const pattern = this.generatePattern(event);
        if (pattern && pattern.confidence >= 0.6) {
            this.candidatePatterns.push(pattern);
            return pattern;
        }
        return null;
    }

    private generatePattern(event: RavenIntelligenceEvent): CandidatePattern | null {
        const commands = event.commands!.join(' ').toLowerCase();

        // SQL Injection patterns
        if (event.cwe === 'CWE-89' || commands.includes('sqlmap') || commands.includes('sql')) {
            return {
                proposedType: `Learned: SQL Injection (attacker-observed)`,
                proposedRegex: `(?:execute|query|raw)\\s*\\(\\s*[\`'"](?:SELECT|INSERT|UPDATE|DELETE)`,
                severity: 'critical',
                languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby'],
                confidence: 0.85,
                attackerBehavior: `Attacker used SQL injection techniques (${event.commands?.slice(0, 3).join(', ')})`,
                cwe: 'CWE-89',
            };
        }

        // Hardcoded credential patterns
        if (event.cwe === 'CWE-798' || commands.includes('cat .env') || commands.includes('credentials')) {
            return {
                proposedType: 'Learned: Credential Exposure (attacker-observed)',
                proposedRegex: `(?:password|secret|token|key|api[_-]?key)\\s*[:=]\\s*[\`'"][^\`'"]{8,}[\`'"]`,
                severity: 'critical',
                languages: ['*'],
                confidence: 0.80,
                attackerBehavior: `Attacker searched for credentials (${event.commands?.slice(0, 3).join(', ')})`,
                cwe: 'CWE-798',
            };
        }

        // Command Injection patterns
        if (event.cwe === 'CWE-78' || commands.includes('cmd') || commands.includes('exec')) {
            return {
                proposedType: 'Learned: Command Injection (attacker-observed)',
                proposedRegex: `(?:exec|spawn|system|popen|subprocess)\\s*\\(\\s*[^)]*\\+[^)]*\\)`,
                severity: 'critical',
                languages: ['javascript', 'typescript', 'python', 'ruby', 'go'],
                confidence: 0.75,
                attackerBehavior: `Attacker used command injection (${event.commands?.slice(0, 3).join(', ')})`,
                cwe: 'CWE-78',
            };
        }

        // Path traversal
        if (event.cwe === 'CWE-22' || commands.includes('/etc/passwd') || commands.includes('../')) {
            return {
                proposedType: 'Learned: Path Traversal (attacker-observed)',
                proposedRegex: `(?:readFile|open|require)\\s*\\(\\s*[^)]*\\.\\.\\/[^)]*\\)`,
                severity: 'high',
                languages: ['javascript', 'typescript', 'python', 'ruby'],
                confidence: 0.70,
                attackerBehavior: `Attacker attempted path traversal (${event.commands?.slice(0, 3).join(', ')})`,
                cwe: 'CWE-22',
            };
        }

        return null;
    }

    getCandidates(): CandidatePattern[] {
        return [...this.candidatePatterns];
    }

    getCandidatesByConfidence(minConfidence: number): CandidatePattern[] {
        return this.candidatePatterns.filter(p => p.confidence >= minConfidence);
    }

    clearApproved(candidates: CandidatePattern[]): void {
        this.candidatePatterns = this.candidatePatterns.filter(
            c => !candidates.some(a => a.proposedType === c.proposedType)
        );
    }

    getSummary(): { total: number; bySeverity: Record<string, number> } {
        const bySeverity: Record<string, number> = {};
        this.candidatePatterns.forEach(p => {
            bySeverity[p.severity] = (bySeverity[p.severity] || 0) + 1;
        });
        return { total: this.candidatePatterns.length, bySeverity };
    }
}
