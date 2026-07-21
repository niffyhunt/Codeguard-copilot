/**
 * CodeGuard → Raven Threat Feedback.
 * When CodeGuard identifies a security weakness, this module generates
 * structured intelligence that Raven can use to understand exploitability.
 *
 * Maps CodeGuard findings to MITRE ATT&CK techniques + Raven CWE priorities.
 */
export interface FindingIntelligence {
    cwe: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    filePath: string;
    language: string;
    mitreTechniques: string[];
    mitreTactics: string[];
    exploitationComplexity: 'low' | 'medium' | 'high';
    attackVector: 'network' | 'local' | 'adjacent';
    ravenPriorityScore: number;
    confidence: number;
    remediationGuidance: string;
}

const CWE_TO_MITRE: Record<string, { techniques: string[]; tactics: string[] }> = {
    'CWE-89': { techniques: ['T1190', 'T1505'], tactics: ['TA0001', 'TA0006'] },
    'CWE-78': { techniques: ['T1059', 'T1203'], tactics: ['TA0002', 'TA0001'] },
    'CWE-79': { techniques: ['T1189', 'T1059'], tactics: ['TA0001', 'TA0002'] },
    'CWE-798': { techniques: ['T1552', 'T1078'], tactics: ['TA0006', 'TA0003'] },
    'CWE-22':  { techniques: ['T1083', 'T1005'], tactics: ['TA0007', 'TA0009'] },
    'CWE-502': { techniques: ['T1505', 'T1059'], tactics: ['TA0002', 'TA0001'] },
    'CWE-327': { techniques: ['T1600', 'T1555'], tactics: ['TA0005', 'TA0006'] },
    'CWE-434': { techniques: ['T1608', 'T1105'], tactics: ['TA0011', 'TA0011'] },
    'CWE-287': { techniques: ['T1078', 'T1110'], tactics: ['TA0001', 'TA0006'] },
    'CWE-918': { techniques: ['T1190', 'T1105'], tactics: ['TA0001', 'TA0011'] },
};

const SEVERITY_SCORES: Record<string, number> = {
    'critical': 90,
    'high': 70,
    'medium': 50,
    'low': 30,
};

export class RavenThreatFeedback {
    generateIntelligence(
        cwe: string,
        severity: 'critical' | 'high' | 'medium' | 'low',
        filePath: string,
        language: string,
        remediation: string,
        findingConfidence: number = 0.8
    ): FindingIntelligence {
        const mitre = CWE_TO_MITRE[cwe] || { techniques: ['T1595'], tactics: ['TA0043'] };
        const baseScore = SEVERITY_SCORES[severity] || 50;

        const attackVector: 'network' | 'local' | 'adjacent' =
            cwe.startsWith('CWE-89') || cwe.startsWith('CWE-79') || cwe.startsWith('CWE-918') ? 'network' :
            cwe.startsWith('CWE-78') ? 'adjacent' : 'local';

        const complexity: 'low' | 'medium' | 'high' =
            cwe.startsWith('CWE-798') || cwe.startsWith('CWE-327') ? 'low' :
            cwe.startsWith('CWE-89') || cwe.startsWith('CWE-78') ? 'medium' : 'high';

        return {
            cwe,
            severity,
            filePath,
            language,
            mitreTechniques: mitre.techniques,
            mitreTactics: mitre.tactics,
            exploitationComplexity: complexity,
            attackVector,
            ravenPriorityScore: Math.round(baseScore * findingConfidence),
            confidence: findingConfidence,
            remediationGuidance: remediation,
        };
    }

    generateFeedbackReport(findings: FindingIntelligence[]): string {
        const critical = findings.filter(f => f.ravenPriorityScore >= 80);
        const high = findings.filter(f => f.ravenPriorityScore >= 60 && f.ravenPriorityScore < 80);

        return [
            `CodeGuard → Raven Threat Feedback Report`,
            `=========================================`,
            `Total findings: ${findings.length}`,
            `Critical (≥80): ${critical.length}`,
            `High (60-79): ${high.length}`,
            ``,
            `Top attack vectors:`,
            ...this.topNWords(findings.map(f => f.attackVector), 3).map(
                ([v, c]) => `  ${v}: ${c} findings`
            ),
            ``,
            `Top MITRE tactics:`,
            ...this.topNWords(findings.flatMap(f => f.mitreTactics), 5).map(
                ([t, c]) => `  ${t}: ${c} findings`
            ),
            ``,
            `Generated: ${new Date().toISOString()}`,
        ].join('\n');
    }

    private topNWords(words: string[], n: number): [string, number][] {
        const counts = new Map<string, number>();
        words.forEach(w => counts.set(w, (counts.get(w) || 0) + 1));
        return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
    }
}
