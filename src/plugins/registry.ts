/**
 * CodeGuard Copilot Plugin System.
 * Allows custom analyzers to be loaded as plugins.
 * Plugins implement the SecurityAnalyzer interface and can add
 * patterns, custom scanning logic, or AI providers.
 */
export interface SecurityAnalyzer {
    name: string;
    version: string;
    description: string;
    initialize(): Promise<void>;
    analyze(code: string, languageId: string): Promise<PluginFinding[]>;
    getPatterns?(): any[];
    cleanup(): void;
}

export interface PluginFinding {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    line: number;
    column: number;
    length: number;
    message: string;
    explanation: string;
    fix: string;
    cwe?: string;
    pluginSource: string;
}

export interface PluginMetadata {
    name: string;
    version: string;
    description: string;
    author: string;
    homepage?: string;
    languages: string[];
    capabilities: ('pattern' | 'analysis' | 'ai' | 'fix')[];
}

export class PluginRegistry {
    private plugins: Map<string, SecurityAnalyzer> = new Map();
    private metadata: Map<string, PluginMetadata> = new Map();

    async registerPlugin(
        metadata: PluginMetadata,
        analyzer: SecurityAnalyzer
    ): Promise<void> {
        this.metadata.set(metadata.name, metadata);
        this.plugins.set(metadata.name, analyzer);
        await analyzer.initialize();
        console.log(`🔌 Plugin registered: ${metadata.name} v${metadata.version}`);
    }

    unregisterPlugin(name: string): void {
        const plugin = this.plugins.get(name);
        if (plugin) {
            plugin.cleanup();
            this.plugins.delete(name);
            this.metadata.delete(name);
        }
    }

    async analyze(
        code: string,
        languageId: string,
        pluginNames?: string[]
    ): Promise<PluginFinding[]> {
        const findings: PluginFinding[] = [];
        const analyzers = pluginNames
            ? pluginNames.map(n => this.plugins.get(n)).filter(Boolean)
            : [...this.plugins.values()];

        for (const a of analyzers) {
            if (!a) continue;
            try {
                const result = await a.analyze(code, languageId);
                findings.push(...result);
            } catch (error) {
                console.error(`Plugin ${a.name} failed:`, error);
            }
        }

        return findings;
    }

    getPlugins(): PluginMetadata[] {
        return [...this.metadata.values()];
    }

    getPluginCount(): number {
        return this.plugins.size;
    }

    hasPluginForLanguage(languageId: string): boolean {
        for (const meta of this.metadata.values()) {
            if (meta.languages.includes('*') || meta.languages.includes(languageId)) {
                return true;
            }
        }
        return false;
    }
}
