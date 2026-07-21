import * as vscode from 'vscode';
import { SecurityPattern } from '../patterns/vulnerabilityPatterns';

/**
 * .codeguard.json custom rules loader.
 * Reads .codeguard.json from workspace root. Supports:
 *   - custom patterns (regex, severity, CWE)
 *   - severity overrides
 *   - path exclusions
 *   - rule suppressions
 *   - shared rule sets (team collaboration)
 */
interface CodeguardConfig {
    version: string;
    rules?: Array<{
        id: string;
        enabled: boolean;
        overrides?: { severity?: string; confidence?: string };
    }>;
    customPatterns?: Array<{
        id: string;
        type: string;
        severity: 'critical' | 'high' | 'medium' | 'low';
        regex: string;
        languages: string[];
        message: string;
        explanation?: string;
        fix?: string;
        cwe?: string;
    }>;
    severityOverrides?: Record<string, string>;
    excludedPaths?: string[];
    suppressions?: Record<string, string[]>;
    sharedRules?: {
        remote?: string;
        local?: string;
    };
}

export class CustomRulesLoader {
    private config: CodeguardConfig | null = null;
    private configWatcher: vscode.FileSystemWatcher | null = null;

    async loadConfig(): Promise<CodeguardConfig | null> {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            return null;
        }

        const configPath = vscode.Uri.joinPath(
            workspaceFolders[0].uri,
            '.codeguard.json'
        );

        try {
            const raw = await vscode.workspace.fs.readFile(configPath);
            const text = new TextDecoder().decode(raw);
            this.config = JSON.parse(text);
            console.log(`📋 Loaded .codeguard.json: ${this.config.customPatterns?.length || 0} custom patterns`);
            return this.config;
        } catch {
            return null;
        }
    }

    getConfig(): CodeguardConfig | null {
        return this.config;
    }

    getCustomPatterns(): SecurityPattern[] {
        if (!this.config?.customPatterns) return [];
        return this.config.customPatterns.map(p => ({
            type: p.type,
            severity: p.severity,
            regex: new RegExp(p.regex, 'gi'),
            languages: p.languages,
            message: p.message,
            explanation: p.explanation || `Custom rule: ${p.type}`,
            fix: p.fix || 'Review and apply appropriate fix for this custom pattern.',
            cwe: p.cwe,
        }));
    }

    isPathExcluded(filePath: string): boolean {
        if (!this.config?.excludedPaths) return false;
        const normalized = filePath.replace(/\\/g, '/');
        return this.config.excludedPaths.some(p => normalized.includes(p));
    }

    getSeverityOverride(patternType: string): string | undefined {
        return this.config?.severityOverrides?.[patternType];
    }

    isRuleSuppressed(patternType: string, filePath: string): boolean {
        if (!this.config?.suppressions) return false;
        const suppressions = this.config.suppressions[patternType] || [];
        return suppressions.some(p => filePath.includes(p));
    }

    watchConfig(callback: () => void): vscode.Disposable {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            return { dispose: () => {} };
        }

        const pattern = new vscode.RelativePattern(
            workspaceFolders[0],
            '.codeguard.json'
        );

        this.configWatcher = vscode.workspace.createFileSystemWatcher(pattern);
        this.configWatcher.onDidChange(async () => {
            await this.loadConfig();
            callback();
        });
        this.configWatcher.onDidCreate(async () => {
            await this.loadConfig();
            callback();
        });
        return this.configWatcher;
    }

    dispose(): void {
        this.configWatcher?.dispose();
    }
}
