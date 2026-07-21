/**
 * Security Finding Knowledge Graph.
 * Connects finding → file → function → dependency → CWE → CVE
 * → MITRE technique → attacker behavior → Raven event → remediation
 * → developer feedback.
 */
export interface KnowledgeNode {
    id: string;
    type: 'finding' | 'file' | 'function' | 'dependency' | 'cwe' | 'cve'
        | 'mitre_technique' | 'attacker_behavior' | 'raven_event'
        | 'remediation' | 'developer_feedback';
    label: string;
    properties: Record<string, any>;
    createdAt: string;
}

export interface KnowledgeEdge {
    from: string;
    to: string;
    type: 'detected_in' | 'maps_to' | 'exploited_by' | 'fixed_by'
        | 'correlated_with' | 'feedback_on';
    weight: number;
}

export class SecurityKnowledgeGraph {
    private nodes: Map<string, KnowledgeNode> = new Map();
    private edges: KnowledgeEdge[] = [];

    addNode(node: KnowledgeNode): void {
        this.nodes.set(node.id, node);
    }

    addEdge(edge: KnowledgeEdge): void {
        if (this.nodes.has(edge.from) && this.nodes.has(edge.to)) {
            this.edges.push(edge);
        }
    }

    linkFindingToCWE(findingId: string, fileId: string, cweId: string): void {
        this.addEdge({ from: findingId, to: fileId, type: 'detected_in', weight: 1.0 });
        this.addEdge({ from: findingId, to: cweId, type: 'maps_to', weight: 0.9 });
    }

    linkCWEDToMITRE(cweId: string, techniqueId: string): void {
        this.addEdge({ from: cweId, to: techniqueId, type: 'maps_to', weight: 0.7 });
    }

    linkToAttackerBehavior(findingId: string, behaviorId: string): void {
        this.addEdge({ from: findingId, to: behaviorId, type: 'correlated_with', weight: 0.6 });
    }

    linkRemediation(findingId: string, remediationId: string): void {
        this.addEdge({ from: findingId, to: remediationId, type: 'fixed_by', weight: 1.0 });
    }

    linkDeveloperFeedback(findingId: string, feedbackId: string): void {
        this.addEdge({ from: findingId, to: feedbackId, type: 'feedback_on', weight: 0.8 });
    }

    getAttackPath(findingId: string): KnowledgeEdge[][] {
        const visited = new Set<string>();
        const paths: KnowledgeEdge[][] = [];

        const dfs = (currentId: string, currentPath: KnowledgeEdge[]) => {
            if (visited.has(currentId)) return;
            visited.add(currentId);

            const outgoing = this.edges.filter(e => e.from === currentId);
            if (outgoing.length === 0) {
                paths.push([...currentPath]);
                return;
            }

            for (const edge of outgoing) {
                dfs(edge.to, [...currentPath, edge]);
            }

            visited.delete(currentId);
        };

        dfs(findingId, []);
        return paths;
    }

    getExploitabilityScore(findingId: string): number {
        const edges = this.edges.filter(e => e.from === findingId);
        if (edges.length === 0) return 0;

        const hasAttackerCorrelation = edges.some(e => e.type === 'correlated_with');
        const hasMITRE = edges.some(e => e.type === 'maps_to');
        const hasFix = edges.some(e => e.type === 'fixed_by');

        let score = 0;
        if (hasMITRE) score += 30;
        if (hasAttackerCorrelation) score += 40;
        if (!hasFix) score += 20;

        return Math.min(100, score);
    }

    getStats(): { nodes: number; edges: number; byType: Record<string, number> } {
        const byType: Record<string, number> = {};
        this.nodes.forEach(n => {
            byType[n.type] = (byType[n.type] || 0) + 1;
        });
        return { nodes: this.nodes.size, edges: this.edges.length, byType };
    }

    exportGraph(): { nodes: KnowledgeNode[]; edges: KnowledgeEdge[] } {
        return {
            nodes: [...this.nodes.values()],
            edges: [...this.edges],
        };
    }

    clear(): void {
        this.nodes.clear();
        this.edges = [];
    }
}
