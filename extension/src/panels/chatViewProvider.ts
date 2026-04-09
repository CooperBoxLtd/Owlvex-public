import * as vscode from 'vscode';
import * as path from 'path';
import { ProviderRegistry } from '../providers/registry';
import { collectScannableFiles } from '../scanner/workspaceScanner';
import { formatFrameworkSummary } from '../frameworks/catalog';

type ChatRole = 'user' | 'assistant' | 'system';
type MessageKind = 'advisory' | 'scan';

interface ChatMessage {
    role: ChatRole;
    content: string;
    kind?: MessageKind;
}

interface EditorContext {
    summary: string;
    promptContext: string;
}

interface LocalActionResult {
    handled: boolean;
    response?: string;
    kind?: MessageKind;
}

type ChatActionKind = 'scanFile' | 'scanFolder' | 'scanReport';

interface ChatLocalIntent {
    action: ChatActionKind;
    fileHint?: string;
}

interface ChatState {
    provider: string;
    providerId: string;
    model: string;
    models: string[];
    providers: Array<{ id: string; name: string }>;
    messages: ChatMessage[];
    editorSummary: string;
    frameworksLabel: string;
    severityThreshold: string;
    workspaceSummary: string;
    lastScanTarget: string;
}

const CHAT_STATE_KEY = 'owlvex.chat.messages';
const LAST_SCAN_TARGET_KEY = 'owlvex.chat.lastScanTarget';
const MAX_PERSISTED_MESSAGES = 40;

function summarizeIssueFamilies(findings: Array<{ canonicalFamilyLabel?: string; canonicalFamily?: string }>): string {
    const labels = [...new Set(
        findings
            .map(item => item.canonicalFamilyLabel || item.canonicalFamily)
            .filter((value): value is string => Boolean(value))
    )];

    if (!labels.length) {
        return 'Issue families: unresolved';
    }

    return `Issue families: ${labels.join(', ')}`;
}

export class ChatViewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'owlvex.chat';

    private view?: vscode.WebviewView;
    private readonly messages: ChatMessage[];

    constructor(
        private readonly registry: ProviderRegistry,
        private readonly storage: vscode.Memento,
    ) {
        this.messages = this.storage.get<ChatMessage[]>(CHAT_STATE_KEY, [
            {
                role: 'system',
                content: 'Owlvex Assistant is ready. Ask about the repo, a vulnerability, remediation ideas, or what to scan next.',
                kind: 'advisory',
            },
        ]);
    }

    resolveWebviewView(view: vscode.WebviewView): void | Thenable<void> {
        this.view = view;
        view.webview.options = { enableScripts: true };
        view.webview.html = this.buildHtml();

        view.webview.onDidReceiveMessage(async (message) => {
            if (message?.type === 'chat:ready') {
                this.refresh();
            }

            if (message?.type === 'chat:send') {
                await this.handleUserMessage(String(message.prompt ?? ''));
            }

            if (message?.type === 'chat:clear') {
                this.messages.splice(1);
                void this.persistState();
                this.refresh();
            }

            if (message?.type === 'chat:setProvider') {
                await this.handleSetProvider(String(message.providerId ?? ''));
            }

            if (message?.type === 'chat:setModel') {
                await this.handleSetModel(String(message.model ?? ''));
            }

            if (message?.type === 'chat:action') {
                await this.handleQuickAction(String(message.action ?? ''));
            }
        });
    }

    async show(): Promise<void> {
        await vscode.commands.executeCommand('owlvex.chat.focus');
    }

    setLastScanTarget(value: string): void {
        void this.storage.update(LAST_SCAN_TARGET_KEY, value);
        this.refresh();
    }

    private async handleUserMessage(prompt: string): Promise<void> {
        const trimmed = prompt.trim();
        if (!trimmed) return;

        this.messages.push({ role: 'user', content: trimmed });
        this.messages.push({ role: 'assistant', content: 'Thinking...', kind: 'advisory' });
        this.refresh();

        try {
            const localAction = await this.tryHandleLocalAction(trimmed);
            if (localAction.handled) {
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    content: localAction.response || 'Completed.',
                    kind: localAction.kind
                        ?? (localAction.response?.includes('Report:') || localAction.response?.includes('Score:')
                            ? 'scan'
                            : 'advisory'),
                };
                void this.persistState();
                this.refresh();
                return;
            }

            const provider = this.registry.getActive();
            const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
            const workspaceSummary = workspaceFolders.length
                ? workspaceFolders.map(folder => folder.name).join(', ')
                : 'No workspace folder is currently open.';
            const editorContext = this.buildEditorContext();
            const scanContext = this.buildScanContext();

            const response = await provider.complete({
                systemPrompt: [
                    'You are Owlvex Assistant, an in-editor AI teammate focused on security and repository-level guidance.',
                    'Be concise, practical, and specific.',
                    'These chat responses are advisory guidance unless the user explicitly triggers a scan action.',
                    `Open workspace folders: ${workspaceSummary}`,
                    scanContext.summary,
                    editorContext.summary,
                ].join('\n'),
                userMessage: `${trimmed}\n\n${scanContext.promptContext}\n\n${editorContext.promptContext}`,
                model: provider.selectedModel,
                temperature: 0.2,
            });

            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: response.content || 'No response returned.',
                kind: 'advisory',
            };
        } catch (error: any) {
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: `Request failed: ${error.message}`,
                kind: 'advisory',
            };
        }

        void this.persistState();
        this.refresh();
    }

    private async tryHandleLocalAction(prompt: string): Promise<LocalActionResult> {
        const intent = parseChatIntent(prompt);
        if (!intent) {
            return { handled: false };
        }

        if (intent.action === 'scanFile') {
            return this.handleScanFileIntent(intent);
        }

        if (intent.action === 'scanFolder') {
            const result = await vscode.commands.executeCommand<any>('owlvex.scanWorkspace');
            if (result?.status === 'cancelled') {
                return { handled: true, response: 'Folder scan was cancelled.', kind: 'scan' };
            }
            if (result?.status === 'empty') {
                return { handled: true, response: 'No supported source files were found in the selected folder.', kind: 'scan' };
            }
            if (!result?.completed) {
                return { handled: true, response: 'Folder scan did not complete.', kind: 'scan' };
            }
            return {
                handled: true,
                response: [
                    `Folder scan completed for ${result.completed} file(s).`,
                    `Total findings: ${result.totalFindings}`,
                    result.results.some((item: any) => item.result.warnings.length)
                        ? `Scan warnings: ${result.results.reduce((total: number, item: any) => total + item.result.warnings.length, 0)}`
                        : 'No scan warnings were reported.',
                    result.errors.length
                        ? `Scan errors: ${result.errors.length}`
                        : 'No scan errors were reported.',
                ].join('\n'),
                kind: 'scan',
            };
        }

        const result = await vscode.commands.executeCommand<any>('owlvex.scanWorkspaceReport');
            if (result?.status === 'cancelled') {
                return {
                    handled: true,
                    response: 'Report creation was cancelled.',
                    kind: 'scan',
            };
        }
        if (result?.status === 'empty') {
            return {
                handled: true,
                response: 'Report creation could not continue because no supported files were found.',
                kind: 'scan',
            };
        }

        const relativeReportPath = vscode.workspace.asRelativePath(result.reportUri, false);
        return {
            handled: true,
            response: [
                `Vulnerability scan completed for ${result.summary.completed} file(s).`,
                `Total findings: ${result.summary.totalFindings}`,
                `Average score: ${result.averageScore.toFixed(1)}/10`,
                `Report: ${relativeReportPath}`,
                result.summary.errors.length
                    ? `Scan errors: ${result.summary.errors.length}`
                    : 'No scan errors were reported.',
            ].join('\n'),
            kind: 'scan',
        };
    }

    private refresh(): void {
        this.pushState();
    }

    private pushState(): void {
        this.postState(this.buildState(this.getFallbackModels()));
        void this.pushResolvedState();
    }

    private async handleSetProvider(providerId: string): Promise<void> {
        if (!providerId || !this.registry.getProvider(providerId)) return;
        await this.registry.setActiveProvider(providerId);

        const provider = this.registry.getActive();
        const models = await this.getModelsForProvider(provider);
        if (models.length && !models.includes(provider.selectedModel)) {
            provider.selectedModel = models[0];
        }

        this.messages.push({
            role: 'system',
            content: `Provider switched to ${provider.name}.`,
            kind: 'advisory',
        });
        void this.persistState();
        this.refresh();
    }

    private async handleSetModel(model: string): Promise<void> {
        const provider = this.registry.getActive();
        if (!model) return;
        provider.selectedModel = model;
        this.messages.push({
            role: 'system',
            content: `Model switched to ${model}.`,
            kind: 'advisory',
        });
        void this.persistState();
        this.refresh();
    }

    private async handleQuickAction(action: string): Promise<void> {
        if (!action) return;

        if (action === 'selectFrameworks') {
            await vscode.commands.executeCommand('owlvex.selectFrameworks');
            this.refresh();
            return;
        }

        this.messages.push({
            role: 'system',
            content: `Running ${action}...`,
            kind: action === 'scanFile' || action === 'scanFolder' || action === 'scanReport'
                ? 'scan'
                : 'advisory',
        });
        this.refresh();

        try {
            if (action === 'scanFile') {
                const result = await vscode.commands.executeCommand<any>('owlvex.scanFile');
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed' && result.result
                        ? [
                            `Scan completed for the selected file.`,
                            `Score: ${result.result.score.toFixed(1)}/10`,
                            `Findings: ${result.result.findings.length}`,
                            summarizeIssueFamilies(result.result.findings),
                            `Model: ${result.result.model}`,
                            (result.result.warnings ?? []).length
                                ? `Warnings: ${(result.result.warnings ?? []).join(' | ')}`
                                : 'No scan warnings were reported.',
                            `Summary: ${result.result.summary || 'No summary returned.'}`,
                        ].join('\n')
                        : 'File scan did not complete.',
                };
            } else if (action === 'scanFolder') {
                const result = await vscode.commands.executeCommand<any>('owlvex.scanWorkspace');
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed'
                        ? [
                            `Folder scan completed.`,
                            `Files scanned: ${result.completed}`,
                            `Total findings: ${result.totalFindings}`,
                            summarizeIssueFamilies(result.results.flatMap((item: any) => item.result.findings)),
                            result.results.some((item: any) => (item.result.warnings ?? []).length)
                                ? `Scan warnings: ${result.results.reduce((total: number, item: any) => total + (item.result.warnings ?? []).length, 0)}`
                                : 'No scan warnings were reported.',
                            result.errors.length
                                ? `Scan errors: ${result.errors.length}`
                                : 'No scan errors were reported.',
                        ].join('\n')
                        : result?.status === 'empty'
                            ? 'No supported source files were found in the selected folder.'
                            : 'Folder scan was cancelled.',
                };
            } else if (action === 'scanReport') {
                const result = await vscode.commands.executeCommand<any>('owlvex.scanWorkspaceReport');
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed' && result.summary
                        ? [
                            `Vulnerability scan completed for ${result.summary.completed} file(s).`,
                            `Total findings: ${result.summary.totalFindings}`,
                            `Average score: ${result.averageScore.toFixed(1)}/10`,
                            summarizeIssueFamilies(result.summary.results.flatMap((item: any) => item.result.findings)),
                            result.summary.results.some((item: any) => (item.result.warnings ?? []).length)
                                ? `Scan warnings: ${result.summary.results.reduce((total: number, item: any) => total + (item.result.warnings ?? []).length, 0)}`
                                : 'No scan warnings were reported.',
                            `Report: ${vscode.workspace.asRelativePath(result.reportUri, false)}`,
                        ].join('\n')
                        : result?.status === 'empty'
                            ? 'Report creation could not continue because no supported files were found.'
                            : 'Report creation was cancelled.',
                };
            } else {
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'advisory',
                    content: `Unknown action: ${action}`,
                };
            }
        } catch (error: any) {
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                kind: action === 'scanFile' || action === 'scanFolder' || action === 'scanReport' ? 'scan' : 'advisory',
                content: `Action failed: ${error.message}`,
            };
        }

        void this.persistState();
        this.refresh();
    }

    private async persistState(): Promise<void> {
        const persisted = this.messages.slice(-MAX_PERSISTED_MESSAGES);
        await this.storage.update(CHAT_STATE_KEY, persisted);
    }

    private async handleScanFileIntent(intent: ChatLocalIntent): Promise<LocalActionResult> {
        const targetUri = intent.fileHint
            ? await this.resolveFileIntentTarget(intent.fileHint)
            : undefined;
        const result = await vscode.commands.executeCommand<any>('owlvex.scanFile', targetUri);

        if (result?.status === 'cancelled') {
            return {
                handled: true,
                response: targetUri
                    ? `File scan was cancelled for ${path.basename(targetUri.fsPath)}.`
                    : 'File scan was cancelled.',
                kind: 'scan',
            };
        }

        if (!result?.result) {
            return { handled: true, response: 'File scan did not complete.', kind: 'scan' };
        }

        const relativePath = result.uri
            ? vscode.workspace.asRelativePath(result.uri, false)
            : (intent.fileHint ?? 'the selected file');
        return {
            handled: true,
            response: [
                `File scan completed for ${relativePath}.`,
                `Score: ${result.result.score.toFixed(1)}/10`,
                `Findings: ${result.result.findings.length}`,
                summarizeIssueFamilies(result.result.findings),
                `Model: ${result.result.model}`,
                (result.result.warnings ?? []).length
                    ? `Warnings: ${(result.result.warnings ?? []).join(' | ')}`
                    : 'No scan warnings were reported.',
                `Summary: ${result.result.summary || 'No summary returned.'}`,
            ].join('\n'),
            kind: 'scan',
        };
    }

    private buildState(models: string[]): ChatState {
        const editorContext = this.buildEditorContext();
        const provider = this.registry.getActive();
        return {
            provider: provider.name,
            providerId: provider.id,
            model: provider.selectedModel,
            models,
            providers: this.registry.allProviders().map(item => ({ id: item.id, name: item.name })),
            messages: this.messages,
            editorSummary: editorContext.summary,
            frameworksLabel: formatFrameworkSummary(this.getFrameworks()),
            severityThreshold: this.getSeverityThreshold(),
            workspaceSummary: this.getWorkspaceSummary(),
            lastScanTarget: this.storage.get<string>(LAST_SCAN_TARGET_KEY, 'No scan run yet'),
        };
    }

    private postState(state: ChatState): void {
        this.view?.webview.postMessage({
            type: 'chat:state',
            ...state,
        });
    }

    private getFallbackModels(): string[] {
        const provider = this.registry.getActive();
        return provider.selectedModel ? [provider.selectedModel] : [];
    }

    private async pushResolvedState(): Promise<void> {
        const provider = this.registry.getActive();
        const models = await this.getModelsForProvider(provider);
        this.postState(this.buildState(models));
    }

    private async getModelsForProvider(provider: ReturnType<ProviderRegistry['getActive']>): Promise<string[]> {
        try {
            const models = await provider.listModels();
            if (models.length) return models;
        } catch {
            // Ignore list failures and fall back to current model.
        }
        return [provider.selectedModel];
    }

    private async resolveFileIntentTarget(fileHint: string): Promise<vscode.Uri | undefined> {
        const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
        if (!workspaceFolders.length) return undefined;

        const candidates: Array<{ uri: vscode.Uri; score: number }> = [];
        for (const folder of workspaceFolders) {
            const files = await collectScannableFiles(folder.uri, 300);
            for (const uri of files) {
                const score = scoreFileMatch(fileHint, uri);
                if (score > 0) {
                    candidates.push({ uri, score });
                }
            }
        }

        candidates.sort((left, right) => right.score - left.score);
        return candidates[0]?.uri;
    }

    private buildEditorContext(): EditorContext {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return {
                summary: 'Active editor: none',
                promptContext: 'No active editor is open.',
            };
        }

        const doc = editor.document;
        const relativePath = vscode.workspace.asRelativePath(doc.uri, false);
        const selectionText = editor.selection.isEmpty ? '' : doc.getText(editor.selection);
        const fullText = doc.getText();
        const trimmedFileText = fullText.length > 12000
            ? `${fullText.slice(0, 12000)}\n\n[truncated after 12000 characters]`
            : fullText;
        const trimmedSelection = selectionText.length > 4000
            ? `${selectionText.slice(0, 4000)}\n\n[selection truncated after 4000 characters]`
            : selectionText;

        return {
            summary: selectionText
                ? `Active editor: ${relativePath} with a code selection`
                : `Active editor: ${relativePath}`,
            promptContext: [
                `Active file: ${relativePath}`,
                `Language: ${doc.languageId}`,
                selectionText
                    ? `Selected code:\n${trimmedSelection}`
                    : 'Selected code: none',
                `Current file excerpt:\n${trimmedFileText}`,
            ].join('\n\n'),
        };
    }

    private buildScanContext(): EditorContext {
        const frameworks = this.getFrameworks();
        const severity = this.getSeverityThreshold();
        const teamContext = vscode.workspace.getConfiguration('owlvex').get<string>('teamContext', '').trim();

        return {
            summary: `Active scan profile: frameworks=${frameworks.join(', ') || 'none'}, severity threshold=${severity}`,
            promptContext: [
                `Security frameworks in scope: ${frameworks.join(', ') || 'none configured'}`,
                `Severity threshold: ${severity}`,
                teamContext ? `Team/project context: ${teamContext}` : 'Team/project context: none',
            ].join('\n'),
        };
    }

    private getFrameworks(): string[] {
        return vscode.workspace.getConfiguration('owlvex').get<string[]>('frameworks', ['OWASP', 'STRIDE']);
    }

    private getSeverityThreshold(): string {
        return vscode.workspace.getConfiguration('owlvex').get<string>('severityThreshold', 'MEDIUM');
    }

    private getWorkspaceSummary(): string {
        const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
        if (!workspaceFolders.length) return 'No workspace folder open';
        return workspaceFolders.map(folder => folder.name).join(', ');
    }

    private buildHtml(): string {
        const nonce = getNonce();

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
  <style>
    body {
      margin: 0;
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
    }
    .shell {
      display: grid;
      grid-template-rows: auto 1fr auto;
      height: 100vh;
    }
    .header {
      padding: 12px 14px;
      border-bottom: 1px solid var(--vscode-sideBarSectionHeader-border);
      background: linear-gradient(135deg, var(--vscode-editorWidget-background), var(--vscode-sideBar-background));
    }
    .title {
      font-size: 13px;
      font-weight: 700;
    }
    .meta {
      margin-top: 4px;
      font-size: 11px;
      opacity: 0.75;
    }
    .controls {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-top: 10px;
    }
    .quick-actions {
      display: flex;
      gap: 8px;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    .chip {
      border: 1px solid var(--vscode-button-border, var(--vscode-widget-border));
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border-radius: 999px;
      padding: 6px 10px;
      font: inherit;
      font-size: 11px;
      cursor: pointer;
    }
    select {
      width: 100%;
      box-sizing: border-box;
      border-radius: 8px;
      padding: 8px 10px;
      color: var(--vscode-input-foreground);
      background: var(--vscode-dropdown-background);
      border: 1px solid var(--vscode-dropdown-border);
      font: inherit;
    }
    .messages {
      overflow-y: auto;
      padding: 14px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .msg {
      max-width: 92%;
      padding: 10px 12px;
      border-radius: 12px;
      white-space: pre-wrap;
      line-height: 1.45;
      word-break: break-word;
      font-size: 12px;
    }
    .tag {
      display: inline-block;
      margin-bottom: 6px;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 10px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      opacity: 0.9;
    }
    .tag.advisory {
      background: color-mix(in srgb, var(--vscode-textLink-foreground) 18%, transparent);
      color: var(--vscode-textLink-foreground);
    }
    .tag.scan {
      background: color-mix(in srgb, var(--vscode-testing-iconPassed) 22%, transparent);
      color: var(--vscode-testing-iconPassed);
    }
    .msg.user {
      align-self: flex-end;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
    }
    .msg.assistant, .msg.system {
      align-self: flex-start;
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-widget-border);
    }
    .composer {
      border-top: 1px solid var(--vscode-sideBarSectionHeader-border);
      padding: 12px;
      display: grid;
      gap: 8px;
    }
    textarea {
      width: 100%;
      min-height: 88px;
      resize: vertical;
      box-sizing: border-box;
      border-radius: 10px;
      padding: 10px 12px;
      color: var(--vscode-input-foreground);
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border);
      font: inherit;
    }
    .actions {
      display: flex;
      gap: 8px;
      justify-content: flex-end;
    }
    button {
      border: none;
      border-radius: 8px;
      padding: 8px 12px;
      font: inherit;
      cursor: pointer;
    }
    button.primary {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
    }
    button.secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="header">
      <div class="title">Owlvex Assistant</div>
      <div class="meta" id="meta">Connecting...</div>
      <div class="meta" id="workspace">Workspace: loading...</div>
      <div class="meta" id="editor">Inspecting editor...</div>
      <div class="meta" id="scanProfile">Loading scan profile...</div>
      <div class="meta" id="lastScan">Last scan target: none</div>
      <div class="controls">
        <select id="provider"></select>
        <select id="model"></select>
      </div>
      <div class="quick-actions">
        <button class="chip" data-action="selectFrameworks">Select Frameworks</button>
        <button class="chip" data-action="scanFile">Scan Current File</button>
        <button class="chip" data-action="scanFolder">Scan Folder</button>
        <button class="chip" data-action="scanReport">Create Report</button>
      </div>
    </div>
    <div class="messages" id="messages"></div>
    <div class="composer">
      <textarea id="prompt" placeholder="Ask Owlvex about this repo, a vulnerability, or what to scan next."></textarea>
      <div class="actions">
        <button class="secondary" id="clear">Clear</button>
        <button class="primary" id="send">Send</button>
      </div>
    </div>
  </div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const messagesEl = document.getElementById('messages');
    const metaEl = document.getElementById('meta');
    const promptEl = document.getElementById('prompt');
    const workspaceEl = document.getElementById('workspace');
    const editorEl = document.getElementById('editor');
    const scanProfileEl = document.getElementById('scanProfile');
    const lastScanEl = document.getElementById('lastScan');
    const providerEl = document.getElementById('provider');
    const modelEl = document.getElementById('model');

    function render(state) {
      metaEl.textContent = 'Provider: ' + state.provider + ' | Model: ' + state.model;
      workspaceEl.textContent = 'Workspace: ' + (state.workspaceSummary || 'No workspace folder open');
      editorEl.textContent = state.editorSummary || 'Active editor: none';
      scanProfileEl.textContent = 'Frameworks: ' + state.frameworksLabel + ' | Threshold: ' + state.severityThreshold;
      lastScanEl.textContent = 'Last scan target: ' + (state.lastScanTarget || 'No scan run yet');
      providerEl.innerHTML = '';
      for (const provider of state.providers) {
        const option = document.createElement('option');
        option.value = provider.id;
        option.textContent = provider.name;
        option.selected = provider.id === state.providerId;
        providerEl.appendChild(option);
      }

      modelEl.innerHTML = '';
      for (const model of state.models) {
        const option = document.createElement('option');
        option.value = model;
        option.textContent = model;
        option.selected = model === state.model;
        modelEl.appendChild(option);
      }

      messagesEl.innerHTML = '';
      for (const message of state.messages) {
        const div = document.createElement('div');
        div.className = 'msg ' + message.role;
        if (message.role !== 'user' && message.kind) {
          const tag = document.createElement('div');
          tag.className = 'tag ' + message.kind;
          tag.textContent = message.kind === 'scan' ? 'Scan-backed' : 'Advisory';
          div.appendChild(tag);
        }
        const text = document.createElement('div');
        text.textContent = message.content;
        div.appendChild(text);
        messagesEl.appendChild(div);
      }
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    window.addEventListener('message', (event) => {
      const message = event.data;
      if (message.type === 'chat:state') {
        render(message);
      }
    });

    vscode.postMessage({ type: 'chat:ready' });

    function sendPrompt() {
      const prompt = promptEl.value.trim();
      if (!prompt) return;
      vscode.postMessage({ type: 'chat:send', prompt });
      promptEl.value = '';
      promptEl.focus();
    }

    document.getElementById('send').addEventListener('click', sendPrompt);
    document.getElementById('clear').addEventListener('click', () => {
      vscode.postMessage({ type: 'chat:clear' });
    });
    providerEl.addEventListener('change', () => {
      vscode.postMessage({ type: 'chat:setProvider', providerId: providerEl.value });
    });
    modelEl.addEventListener('change', () => {
      vscode.postMessage({ type: 'chat:setModel', model: modelEl.value });
    });
    document.querySelectorAll('[data-action]').forEach((button) => {
      button.addEventListener('click', () => {
        vscode.postMessage({ type: 'chat:action', action: button.getAttribute('data-action') });
      });
    });
    promptEl.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        sendPrompt();
      }
    });
  </script>
</body>
</html>`;
    }
}

export function parseChatIntent(prompt: string): ChatLocalIntent | undefined {
    const normalized = prompt.toLowerCase();
    const wantsScan = /\b(scan|audit|analy[sz]e|analy[sz]is|review)\b/.test(normalized);
    const wantsReport = /\b(report|summary|markdown|document)\b/.test(normalized);
    const wantsFolder = /\b(repo|repository|workspace|folder|project|codebase)\b/.test(normalized);
    const wantsFile = /\b(file|current file|this file|selected file)\b/.test(normalized);
    const explicitFile = extractFileHint(prompt);

    if (wantsScan && wantsReport) {
        return { action: 'scanReport', fileHint: explicitFile };
    }

    if (wantsScan && (wantsFolder || /\bscan folder\b/.test(normalized))) {
        return { action: 'scanFolder' };
    }

    if (wantsScan && (wantsFile || Boolean(explicitFile))) {
        return { action: 'scanFile', fileHint: explicitFile };
    }

    return undefined;
}

function extractFileHint(prompt: string): string | undefined {
    const explicitPath = prompt.match(/[A-Za-z0-9_\-./\\]+?\.(ts|tsx|js|jsx|py|java|cs|go|rs|php|rb|cpp|c|h)\b/i);
    if (explicitPath?.[0]) {
        return explicitPath[0];
    }

    const namedFile = prompt.match(/\b(?:scan|audit|review|analy[sz]e)(?:\s+(?:the|this|that|file|named))?\s+([A-Za-z0-9_\-. ]{3,80})/i);
    if (!namedFile?.[1]) {
        return undefined;
    }

    const cleaned = namedFile[1]
        .replace(/\b(?:and|with|using|please|for)\b.*$/i, '')
        .trim();

    if (!cleaned) {
        return undefined;
    }

    const genericTerms = new Set([
        'file',
        'this file',
        'current file',
        'selected file',
        'repo',
        'repository',
        'workspace',
        'folder',
        'project',
        'codebase',
    ]);

    return genericTerms.has(cleaned.toLowerCase()) ? undefined : cleaned;
}

function scoreFileMatch(fileHint: string, uri: vscode.Uri): number {
    const normalizedHint = normalizeToken(stripKnownExtension(path.basename(fileHint)) || fileHint);
    if (!normalizedHint) return 0;

    const basename = path.basename(uri.fsPath);
    const basenameNoExt = stripKnownExtension(basename);
    const relativePath = vscode.workspace.asRelativePath(uri, false);
    const normalizedBase = normalizeToken(basenameNoExt);
    const normalizedPath = normalizeToken(relativePath);

    if (normalizedBase === normalizedHint) return 100;
    if (normalizedPath.endsWith(normalizedHint)) return 95;
    if (normalizedBase.includes(normalizedHint) || normalizedHint.includes(normalizedBase)) return 90;
    if (normalizedPath.includes(normalizedHint)) return 80;

    const distance = levenshteinDistance(normalizedBase, normalizedHint);
    const maxLength = Math.max(normalizedBase.length, normalizedHint.length);
    if (maxLength > 0 && distance <= 2) {
        return 70 - distance;
    }

    return 0;
}

function stripKnownExtension(value: string): string {
    return value.replace(/\.(ts|tsx|js|jsx|py|java|cs|go|rs|php|rb|cpp|c|h)$/i, '');
}

function normalizeToken(value: string): string {
    return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function levenshteinDistance(left: string, right: string): number {
    const rows = left.length + 1;
    const cols = right.length + 1;
    const matrix = Array.from({ length: rows }, () => Array<number>(cols).fill(0));

    for (let row = 0; row < rows; row++) matrix[row][0] = row;
    for (let col = 0; col < cols; col++) matrix[0][col] = col;

    for (let row = 1; row < rows; row++) {
        for (let col = 1; col < cols; col++) {
            const substitutionCost = left[row - 1] === right[col - 1] ? 0 : 1;
            matrix[row][col] = Math.min(
                matrix[row - 1][col] + 1,
                matrix[row][col - 1] + 1,
                matrix[row - 1][col - 1] + substitutionCost,
            );
        }
    }

    return matrix[rows - 1][cols - 1];
}

function getNonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let value = '';
    for (let i = 0; i < 32; i++) {
        value += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return value;
}
