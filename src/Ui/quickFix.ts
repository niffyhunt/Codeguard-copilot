import * as vscode from 'vscode';
import { AISecurityEngine } from '../ai/aiEngine';

export class SecurityQuickFixProvider implements vscode.CodeActionProvider {
    private aiEngine: AISecurityEngine;

    constructor(aiEngine: AISecurityEngine) {
        this.aiEngine = aiEngine;
    }

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Only provide fixes for Security Co-pilot diagnostics
        const securityDiagnostics = context.diagnostics.filter(
            d => d.source === 'Security Co-pilot'
        );

        securityDiagnostics.forEach(diagnostic => {
            // Create "Explain vulnerability" action
            actions.push(this.createExplainAction(diagnostic));

            // Create "Apply secure fix" action if we have a code example
            const fixAction = this.createFixAction(document, diagnostic);
            if (fixAction) {
                actions.push(fixAction);
            }

            // Create "Learn more" action with CWE link
            if (diagnostic.code) {
                actions.push(this.createLearnMoreAction(diagnostic));
            }

            // Create "Ignore this warning" action
            actions.push(this.createIgnoreAction(document, diagnostic));
        });

        return actions;
    }

    private createExplainAction(diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            '📚 Explain this vulnerability',
            vscode.CodeActionKind.QuickFix
        );

        action.command = {
            title: 'Show Explanation',
            command: 'codeguard.explainVulnerability',
            arguments: [diagnostic]
        };

        action.diagnostics = [diagnostic];
        return action;
    }

    private createFixAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction | null {
        // Extract secure code example from diagnostic info
        const detailedInfo = diagnostic.relatedInformation?.[0]?.message || '';
        const exampleMatch = detailedInfo.match(/💡 SECURE EXAMPLE:\s*([\s\S]*?)(?:\n\n|$)/);
        
        if (!exampleMatch || !exampleMatch[1]) {
            return null;
        }

        const secureCode = exampleMatch[1].trim();
        
        // Extract just the "Good" part if it's in "Bad/Good" format
        const goodMatch = secureCode.match(/\/\/\s*Good:\s*(.+)/);
        const fixCode = goodMatch ? goodMatch[1].trim() : secureCode;

        const action = new vscode.CodeAction(
            '🔧 Apply secure fix',
            vscode.CodeActionKind.QuickFix
        );

        action.isPreferred = true; // Makes it the default quick fix
        action.diagnostics = [diagnostic];

        // Create edit to replace vulnerable code
        action.edit = new vscode.WorkspaceEdit();
        action.edit.replace(
            document.uri,
            diagnostic.range,
            fixCode
        );

        return action;
    }

    private createLearnMoreAction(diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const cwe = diagnostic.code?.toString() || '';
        const cweNumber = cwe.replace('CWE-', '');

        const action = new vscode.CodeAction(
            `📖 Learn more about ${cwe}`,
            vscode.CodeActionKind.QuickFix
        );

        action.command = {
            title: 'Open CWE Documentation',
            command: 'vscode.open',
            arguments: [
                vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweNumber}.html`)
            ]
        };

        action.diagnostics = [diagnostic];
        return action;
    }

    private createIgnoreAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            '🔕 Ignore this warning',
            vscode.CodeActionKind.QuickFix
        );

        // Add a comment to suppress this warning
        const line = document.lineAt(diagnostic.range.start.line);
        const indentation = line.text.match(/^\s*/)?.[0] || '';
        const comment = this.getCommentSyntax(document.languageId);
        
        action.edit = new vscode.WorkspaceEdit();
        action.edit.insert(
            document.uri,
            new vscode.Position(diagnostic.range.start.line, 0),
            `${indentation}${comment} security-copilot-disable-next-line\n`
        );

        action.diagnostics = [diagnostic];
        return action;
    }

    private getCommentSyntax(languageId: string): string {
        const commentMap: Record<string, string> = {
            'javascript': '//',
            'typescript': '//',
            'java': '//',
            'python': '#',
            'php': '//',
            'go': '//',
            'rust': '//',
            'c': '//',
            'cpp': '//',
            'csharp': '//',
        };

        return commentMap[languageId] || '//';
    }
}

// Register this command in extension.ts
export function registerExplainCommand(context: vscode.ExtensionContext): void {
    const command = vscode.commands.registerCommand(
        'codeguard.explainVulnerability',
        (diagnostic: vscode.Diagnostic) => {
            const detailedInfo = diagnostic.relatedInformation?.[0]?.message || 'No details available';

            // Create a webview panel to show detailed explanation
            const panel = vscode.window.createWebviewPanel(
                'securityExplanation',
                `Security: ${diagnostic.message}`,
                vscode.ViewColumn.Beside,
                { enableScripts: false }
            );

            panel.webview.html = getExplanationHTML(diagnostic.message, detailedInfo);
        }
    );

    context.subscriptions.push(command);
}

function getExplanationHTML(title: string, explanation: string): string {
    // Convert explanation text to HTML with proper formatting
    const sections = explanation.split('\n\n');
    const htmlSections = sections.map(section => {
        const lines = section.split('\n');
        const header = lines[0];
        const content = lines.slice(1).join('\n');

        if (header.includes('⚠️') || header.includes('🔧') || header.includes('💡') || header.includes('📚')) {
            return `
                <div class="section">
                    <h3>${header}</h3>
                    <pre>${content}</pre>
                </div>
            `;
        }
        return `<p>${section}</p>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Explanation</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 20px;
            line-height: 1.6;
        }
        h2 {
            color: var(--vscode-textLink-foreground);
            border-bottom: 2px solid var(--vscode-textLink-foreground);
            padding-bottom: 10px;
        }
        h3 {
            color: var(--vscode-textPreformat-foreground);
            margin-top: 20px;
            margin-bottom: 10px;
        }
        .section {
            margin: 20px 0;
            padding: 15px;
            background-color: var(--vscode-textBlockQuote-background);
            border-left: 4px solid var(--vscode-textLink-foreground);
        }
        pre {
            background-color: var(--vscode-textCodeBlock-background);
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: var(--vscode-editor-font-family);
        }
        a {
            color: var(--vscode-textLink-foreground);
        }
    </style>
</head>
<body>
    <h2>${title}</h2>
    ${htmlSections}
</body>
</html>`;
}