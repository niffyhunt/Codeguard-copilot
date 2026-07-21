/**
 * JetBrains IDE Support — Scaffolding.
 * This module provides the architecture for IntelliJ/WebStorm/Rider
 * plugin integration. Full implementation in a JetBrains plugin SDK project.
 *
 * Architecture:
 *   JetBrains Plugin (Kotlin/Java)
 *     → InspectionToolProvider
 *     → CodeGuardAnalyzer (calls shared pattern engine)
 *     → HighlightInfo → IDE Problem Panel
 *
 * The pattern engine (src/patterns/vulnerabilityPatterns.ts + expandedPatterns.ts)
 * is shared between VS Code and JetBrains via a common JSON export.
 */

export interface JetBrainsInspection {
    inspectionId: string;
    displayName: string;
    severity: 'ERROR' | 'WARNING' | 'WEAK_WARNING' | 'INFO';
    description: string;
    fixDescription: string;
    pattern: string;
    languages: string[];
}

export class JetBrainsPatternExporter {
    /**
     * Export CodeGuard patterns to a format compatible with JetBrains inspections.
     * JetBrains plugins consume this JSON to register inspections at runtime.
     */
    exportPatterns(patterns: any[]): JetBrainsInspection[] {
        return patterns.map(p => ({
            inspectionId: `CodeGuard.${p.type.replace(/\s+/g, '')}`,
            displayName: `CodeGuard: ${p.type}`,
            severity: this.mapSeverity(p.severity),
            description: p.explanation || p.message,
            fixDescription: p.fix || 'Review and apply recommended fix.',
            pattern: p.regex instanceof RegExp ? p.regex.source : String(p.regex),
            languages: p.languages,
        }));
    }

    private mapSeverity(s: string): 'ERROR' | 'WARNING' | 'WEAK_WARNING' | 'INFO' {
        switch (s) {
            case 'critical': return 'ERROR';
            case 'high': return 'ERROR';
            case 'medium': return 'WARNING';
            case 'low': return 'WEAK_WARNING';
            default: return 'INFO';
        }
    }
}
