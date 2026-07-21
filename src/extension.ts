import * as vscode from 'vscode';
import { SecurityScanner } from './patterns/securityScanner';
import { AISecurityEngine } from './ai/aiEngine';
import { SecurityDiagnostics } from './Ui/diagnostics';
import { SecurityQuickFixProvider, registerExplainCommand } from './Ui/quickFix';

let diagnosticCollection: vscode.DiagnosticCollection;
let securityScanner: SecurityScanner;
let aiEngine: AISecurityEngine;
let scanTimeout: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('🛡️ Security Co-pilot is now active!');

    // Initialize core components
    diagnosticCollection = vscode.languages.createDiagnosticCollection('security');
    context.subscriptions.push(diagnosticCollection);

    aiEngine = new AISecurityEngine();
    securityScanner = new SecurityScanner(aiEngine);

    // Command: Scan current file
    const scanFileCommand = vscode.commands.registerCommand(
        'codeguard.scanFile',
        async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await scanDocument(editor.document);
                vscode.window.showInformationMessage('✅ Security scan complete!');
            } else {
                vscode.window.showWarningMessage('No active file to scan');
            }
        }
    );

    // Command: Scan entire workspace
    const scanWorkspaceCommand = vscode.commands.registerCommand(
        'codeguard.scanWorkspace',
        async () => {
            const files = await vscode.workspace.findFiles('**/*.{js,ts,py,java,php}');
            let scanned = 0;

            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Scanning workspace for vulnerabilities...',
                cancellable: true
            }, async (progress, token) => {
                for (const file of files) {
                    if (token.isCancellationRequested) break;

                    const doc = await vscode.workspace.openTextDocument(file);
                    await scanDocument(doc);
                    scanned++;

                    progress.report({
                        message: `${scanned}/${files.length} files`,
                        increment: (100 / files.length)
                    });
                }
            });

            vscode.window.showInformationMessage(
                `✅ Scanned ${scanned} files. Check Problems panel for results.`
            );
        }
    );

    // Real-time scanning on document change
    const changeListener = vscode.workspace.onDidChangeTextDocument(async (event) => {
        const config = vscode.workspace.getConfiguration('codeguard');
        const enableRealtime = config.get<boolean>('enableRealtime', true);

        if (!enableRealtime) return;

        // Debounce typing
        if (scanTimeout) clearTimeout(scanTimeout);

        const delay = config.get<number>('scanDelay', 500);
        scanTimeout = setTimeout(async () => {
            await scanDocument(event.document);
        }, delay);
    });

    // Scan on save
    const saveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
        await scanDocument(document);
    });

    // Register quick-fix provider
    const quickFixProvider = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        new SecurityQuickFixProvider(aiEngine),
        {
            providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
        }
    );

    // Status bar item
    const statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBarItem.text = '$(shield) Security Co-pilot';
    statusBarItem.tooltip = 'Click to scan current file';
    statusBarItem.command = 'codeguard.scanFile';
    statusBarItem.show();

    // Register explain vulnerability command (webview panel)
    registerExplainCommand(context);

    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        changeListener,
        saveListener,
        quickFixProvider,
        statusBarItem
    );
}

async function scanDocument(document: vscode.TextDocument): Promise<void> {
    console.log('🔍 Scanning document:', document.fileName, 'Language:', document.languageId);

    // Supported languages
    const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'php'];
    if (!supportedLanguages.includes(document.languageId)) {
        console.log('⏭️ Skipping unsupported language:', document.languageId);
        return;
    }

    try {
        const vulnerabilities = await securityScanner.scan(
            document.getText(),
            document.languageId
        );

        console.log(`✅ Found ${vulnerabilities.length} vulnerabilities`);

        const diagnostics = SecurityDiagnostics.createDiagnostics(
            document,
            vulnerabilities
        );

        diagnosticCollection.set(document.uri, diagnostics);
    } catch (error) {
        console.error('❌ Scan failed:', error);
    }
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}