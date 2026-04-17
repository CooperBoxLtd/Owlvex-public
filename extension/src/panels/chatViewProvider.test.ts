import * as vscode from 'vscode';
import { ChatViewProvider, buildFindingContextSummary, buildFindingPromptContext, buildGroundedRemediationHighlights, buildNearbyProjectContext, extractPatchedFileContent, parseChatIntent } from './chatViewProvider';
import { configureRulePackRuntime, resetRulePackRuntime } from '../frameworks/rulePackRegistry';
import { PROFILE } from '../profile';

describe('parseChatIntent', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        resetRulePackRuntime();
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath ?? String(uri));
    });

    it('routes repo scan report requests to report creation', () => {
        expect(parseChatIntent('scan the repo and create a report')).toEqual({
            action: 'scanReport',
            fileHint: undefined,
        });
    });

    it('routes explicit file scan requests to file scanning', () => {
        expect(parseChatIntent('scan this file')).toEqual({
            action: 'scanFile',
            fileHint: undefined,
        });
    });

    it('extracts a file path when the user names a source file', () => {
        expect(parseChatIntent('scan src/probes/owlvex-probe-safe-baseline.js')).toEqual({
            action: 'scanFile',
            fileHint: 'src/probes/owlvex-probe-safe-baseline.js',
        });
    });

    it('extracts a file-like hint from natural language', () => {
        expect(parseChatIntent('i want to scan owlex-probe-safe-baseline')).toEqual({
            action: 'scanFile',
            fileHint: 'owlex-probe-safe-baseline',
        });
    });

    it('routes folder scan requests to folder scanning', () => {
        expect(parseChatIntent('scan the workspace for issues')).toEqual({
            action: 'scanFolder',
        });
    });

    it('routes selected-files scan requests to selected-files scanning', () => {
        expect(parseChatIntent('scan selected files')).toEqual({
            action: 'scanSelectedFiles',
        });
    });

    it('routes open-editors scan requests to open-editors scanning', () => {
        expect(parseChatIntent('scan open editors')).toEqual({
            action: 'scanOpenEditors',
        });
    });

    it('routes calibration review requests to the risk calibration action', () => {
        expect(parseChatIntent('review scoring posture')).toEqual({
            action: 'reviewRiskCalibration',
        });
    });

    it('returns undefined for normal advisory chat', () => {
        expect(parseChatIntent('hey there')).toBeUndefined();
    });

    it('builds grounded remediation highlights from remediation pack variants', () => {
        configureRulePackRuntime(
            undefined,
            undefined,
            {
                entries: [{
                    id: 'owlvex.remediation.sql_injection.001',
                    issue_id: 'owlvex.issue.sql_injection.001',
                    title: 'Canonical remediation for SQL injection',
                    canonical_fix_summary: 'Use parameter binding.',
                    framework_variants: [{
                        framework: 'Express',
                        summary: 'Use placeholders and values arrays.',
                        recommended_actions: ['Replace string-built SQL with placeholders.'],
                    }],
                    validation_steps: ['Replay SQL metacharacters.'],
                    unsafe_alternatives: ['Manual escaping.'],
                    references: [{
                        label: 'OWASP SQL Injection Prevention Cheat Sheet',
                        kind: 'cheat-sheet',
                    }],
                    provenance: {
                        source_type: 'hybrid',
                        curation_method: 'manual',
                        review_status: 'reviewed',
                        sources: [{ label: 'OWASP SQL Injection Prevention Cheat Sheet', kind: 'cheat-sheet' }],
                    },
                }],
            },
        );

        const highlights = buildGroundedRemediationHighlights([
            {
                id: 'finding-1',
                line: 3,
                lineEnd: 3,
                severity: 'HIGH',
                framework: 'Express',
                ruleCode: 'OWASP-A03',
                title: 'SQL Injection',
                explanation: 'User input is concatenated into SQL.',
                threat: 'Data exposure',
                fix: 'Use parameterized queries.',
                confidence: 0.9,
                canonicalId: 'owlvex.issue.sql_injection.001',
            },
        ] as any);

        expect(highlights).toEqual([
            'SQL Injection: Use placeholders and values arrays. [Express] Use placeholders and values arrays.',
        ]);
    });

    it('builds finding discussion context with remediation and snippet', () => {
        configureRulePackRuntime(
            undefined,
            undefined,
            {
                entries: [{
                    id: 'owlvex.remediation.sql_injection.001',
                    issue_id: 'owlvex.issue.sql_injection.001',
                    title: 'Canonical remediation for SQL injection',
                    canonical_fix_summary: 'Use parameter binding.',
                    framework_variants: [{
                        framework: 'Express',
                        summary: 'Use placeholders and values arrays.',
                        recommended_actions: ['Replace string-built SQL with placeholders.'],
                    }],
                    validation_steps: [],
                    unsafe_alternatives: [],
                    references: [],
                    provenance: {
                        source_type: 'hybrid',
                        curation_method: 'manual',
                        review_status: 'reviewed',
                        sources: [],
                    },
                }],
            },
        );

        const context = buildFindingPromptContext({
            id: 'finding-1',
            line: 9,
            lineEnd: 9,
            severity: 'HIGH',
            framework: 'Express',
            ruleCode: 'SQ-001',
            title: 'SQL Injection',
            explanation: 'User input is concatenated into SQL.',
            threat: 'Data exposure',
            fix: 'Use parameterized queries.',
            confidence: 0.9,
            canonicalId: 'owlvex.issue.sql_injection.001',
            provenance: 'ai',
            likelihood: 'HIGH',
            likelihoodReasons: ['User input reaches the query sink directly.'],
            riskScore: 9,
        } as any, "   8 | const query = `SELECT * FROM users`;");

        expect(context).toContain('Finding selected for discussion:');
        expect(context).toContain('Title: SQL Injection');
        expect(context).toContain('Suggested remediation: Use placeholders and values arrays.');
        expect(context).toContain('Likelihood reasons: User input reaches the query sink directly.');
        expect(context).toContain('Local code snippet:');
    });

    it('builds nearby project context from local imports', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockImplementation(async (uri: any) => {
            if (String(uri.fsPath).endsWith('helper.js')) {
                return Buffer.from([
                    'export function normalize(input) {',
                    '  return input.trim();',
                    '}',
                ].join('\n'));
            }
            throw new Error('not found');
        });

        const context = await buildNearbyProjectContext({
            uri: vscode.Uri.file('d:\\repo\\src\\app.js'),
            getText: () => [
                "import { normalize } from './helper';",
                'export function run(value) {',
                '  return normalize(value);',
                '}',
            ].join('\n'),
        } as any);

        expect(context).toContain('Nearby project context:');
        expect(context).toContain('Imported via: ./helper');
        expect(context).toContain('Referenced symbols: normalize');
        expect(context).toContain('helper.js');
        expect(context).toContain('export function normalize(input) {');
    });

    it('prioritizes imports referenced near the finding lines', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockImplementation(async (uri: any) => {
            if (String(uri.fsPath).endsWith('validator.js')) {
                return Buffer.from('export function validate(input) { return input; }');
            }
            if (String(uri.fsPath).endsWith('unused.js')) {
                return Buffer.from('export function helper() { return true; }');
            }
            throw new Error('not found');
        });

        const context = await buildNearbyProjectContext({
            uri: vscode.Uri.file('d:\\repo\\src\\route.js'),
            getText: () => [
                "import { helper } from './unused';",
                "import { validate } from './validator';",
                'export function handler(input) {',
                '  const clean = validate(input);',
                '  return clean;',
                '}',
            ].join('\n'),
        } as any, { line: 4, lineEnd: 4 } as any, 1);

        expect(context).toContain('Context prioritized around finding lines 4.');
        expect(context).toContain('validator.js');
        expect(context).not.toContain('unused.js');
    });

    it('builds a visible context source summary for finding discussions', () => {
        const summary = buildFindingContextSummary({
            finding: {
                id: 'finding-1',
                line: 4,
                lineEnd: 4,
                severity: 'HIGH',
                framework: 'OWASP',
                ruleCode: 'SQ-001',
                title: 'SQL Injection',
                explanation: 'User input reaches a query sink.',
                threat: 'Data exposure.',
                fix: 'Use parameterized queries.',
                confidence: 0.9,
                provenance: 'ai',
            } as any,
            hasActiveSnippet: true,
            nearbyContext: [
                'Nearby project context:',
                'Nearby context file: src/db/queries.js',
                'Imported via: ./db/queries',
            ].join('\n'),
            hasLatestReportContext: true,
            groundedFrameworks: ['OWASP Top 10 (2021)', 'Common Weakness Enumeration'],
            groundedCheatSheets: ['OWASP SQL Injection Prevention Cheat Sheet'],
        });

        expect(summary).toContain('Context sources used for "SQL Injection":');
        expect(summary).toContain('- Active file snippet around the finding');
        expect(summary).toContain('- Nearby file: src/db/queries.js');
        expect(summary).toContain('- Latest report summary context');
        expect(summary).toContain('- Curated framework pack: OWASP Top 10 (2021), Common Weakness Enumeration');
        expect(summary).toContain('- Curated cheat-sheet pack: OWASP SQL Injection Prevention Cheat Sheet');
    });

    it('starts a fresh chat by default and offers restoring the previous one', () => {
        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
            }),
        } as any, {
            get: jest.fn((key: string, defaultValue?: unknown) => key === `${PROFILE.storagePrefix}.chat.messages`
                ? [
                    { role: 'system', content: 'Owlvex Assistant is ready.', kind: 'advisory' },
                    { role: 'user', content: 'Old question' },
                    { role: 'assistant', content: 'Old answer', kind: 'advisory' },
                ]
                : defaultValue),
            update: jest.fn(),
        } as any);

        expect((provider as any).messages[0].content).toContain('Owlvex Assistant is ready.');
        expect((provider as any).messages[1].content).toContain('Previous chat available');
        expect((provider as any).messages[1].actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ kind: 'restorePreviousChat', label: 'Restore previous chat' }),
            expect.objectContaining({ kind: 'dismissMessage', label: 'Keep this fresh chat' }),
        ]));
    });

    it('extracts patched file content from fenced responses', () => {
        const patched = extractPatchedFileContent([
            '```js',
            'const safe = true;',
            '```',
        ].join('\n'), 'const safe = false;');

        expect(patched).toBe('const safe = true;');
    });

    it('opens a review-only diff preview for a generated fix', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: [
                '```js',
                'const query = "SELECT id FROM users WHERE name = ?";',
                'db.query(query, [name]);',
                '```',
            ].join('\n'),
        });
        const registry = {
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        };
        const storage = {
            get: jest.fn((key: string, defaultValue?: unknown) => {
                if (key === `${PROFILE.storagePrefix}.lastReportSnapshot`) {
                    return {
                        targetLabel: 'tools/demo',
                        results: [{
                            result: {
                                findings: [{
                                    canonicalTitle: 'SQL Injection',
                                    line: 9,
                                    severity: 'HIGH',
                                    explanation: 'Dynamic SQL is built from user input.',
                                    fix: 'Use parameterized queries.',
                                }],
                            },
                        }],
                    };
                }

                return defaultValue;
            }),
            update: jest.fn(),
        };
        const previewUri = { fsPath: 'untitled:fix-preview.js', scheme: 'untitled', toString: () => 'untitled:fix-preview.js' };
        (vscode.workspace.workspaceFolders as any) = [{
            uri: vscode.Uri.file('d:\\repo'),
            name: 'repo',
        }];
        (vscode.workspace.fs.readFile as jest.Mock).mockImplementation(async (uri: any) => {
            if (String(uri.fsPath).endsWith('src\\db.js')) {
                return Buffer.from('export const db = { query() {} };');
            }
            throw new Error('not found');
        });
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: vscode.Uri.file('d:\\repo\\src\\userRepo.js'),
                languageId: 'javascript',
                getText: () => [
                    "import { db } from './db';",
                    'async function findUser(name) {',
                    '  const query = `SELECT id FROM users WHERE name = \'${name}\'`;',
                    '  return db.query(query);',
                    '}',
                ].join('\n'),
            },
            selection: {
                isEmpty: true,
            },
        };
        (vscode.workspace.openTextDocument as jest.Mock).mockResolvedValue({ uri: previewUri });

        const provider = new ChatViewProvider(registry as any, storage as any);
        await provider.generateFixPreview({
            id: 'finding-1',
            line: 3,
            lineEnd: 4,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'SQ-001',
            title: 'SQL Injection',
            explanation: 'Dynamic SQL is built from user input.',
            threat: 'Data exposure.',
            fix: 'Use parameterized queries.',
            confidence: 0.9,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 9,
        } as any);

        expect(complete).toHaveBeenCalledWith(expect.objectContaining({
            model: 'owlvex-test-model',
            systemPrompt: expect.stringContaining('Return only the full updated file contents.'),
            userMessage: expect.stringContaining('Latest report findings: 1'),
        }));
        expect(vscode.workspace.openTextDocument).toHaveBeenCalledWith({
            language: 'javascript',
            content: [
                'const query = "SELECT id FROM users WHERE name = ?";',
                'db.query(query, [name]);',
            ].join('\n'),
        });
        expect(vscode.commands.executeCommand).toHaveBeenNthCalledWith(1, PROFILE.commands.chatFocus);
        expect(vscode.commands.executeCommand).toHaveBeenNthCalledWith(
            2,
            'vscode.diff',
            expect.anything(),
            previewUri,
            `${PROFILE.displayLabel}: Fix Preview - SQL Injection`,
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Review fix ready for');
        expect((provider as any).messages[(provider as any).messages.length - 1].actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ id: 'apply-fix-preview', label: 'Keep fix', kind: 'applyFixPreview' }),
            expect.objectContaining({ id: 'discard-fix-preview', label: 'Discard fix', kind: 'discardFixPreview' }),
        ]));
        expect((provider as any).messages[(provider as any).messages.length - 3].actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Open active file', kind: 'openSource', line: 3 }),
            expect.objectContaining({ label: expect.stringContaining('db.js'), kind: 'openSource' }),
        ]));
    });

    it('does not offer generate fix preview from a stale latest report finding', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Use a parameterized query.' });
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: vscode.Uri.file('d:\\repo\\src\\userRepo.js'),
                languageId: 'javascript',
                getText: () => 'const sql = `SELECT * FROM users WHERE name = ${name}`;',
            },
            selection: { isEmpty: true },
        };
        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        } as any, {
            get: jest.fn((key: string, defaultValue?: unknown) => key === `${PROFILE.storagePrefix}.lastReportSnapshot`
                ? {
                    targetLabel: 'tools/demo',
                    results: [{
                        result: {
                            findings: [{
                                id: 'finding-sql',
                                line: 1,
                                lineEnd: 1,
                                severity: 'HIGH',
                                framework: 'OWASP',
                                ruleCode: 'SQL-001',
                                title: 'SQL Injection',
                                explanation: 'Dynamic SQL is built from user input.',
                                threat: 'Data exposure.',
                                fix: 'Use parameterized queries.',
                                confidence: 0.9,
                                provenance: 'ai',
                                likelihood: 'HIGH',
                                riskScore: 9,
                            }],
                        },
                    }],
                }
                : defaultValue),
            update: jest.fn(),
        } as any);

        await (provider as any).handleUserMessage('Please give me the safe fix for this');

        expect((provider as any).messages[(provider as any).messages.length - 1].actions).toBeUndefined();
    });

    it('does not inject the latest report into a fresh greeting', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Good morning! I am ready to help.' });
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: vscode.Uri.file('d:\\repo\\src\\app.js'),
                languageId: 'javascript',
                getText: () => 'console.log("hello");',
            },
            selection: { isEmpty: true },
        };
        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        } as any, {
            get: jest.fn((key: string, defaultValue?: unknown) => key === `${PROFILE.storagePrefix}.lastReportSnapshot`
                ? {
                    targetLabel: 'tools/demo',
                    results: [{
                        result: {
                            findings: [{
                                id: 'finding-tenant',
                                line: 5,
                                severity: 'CRITICAL',
                                title: 'Multi-Tenant Isolation Failure',
                                explanation: 'Tenant scoping is missing.',
                                fix: 'Scope queries by tenant.',
                            }],
                        },
                    }],
                }
                : defaultValue),
            update: jest.fn(),
        } as any);

        await (provider as any).handleUserMessage("morning you're good ?");

        const request = complete.mock.calls[0][0];
        expect(request.systemPrompt).toContain('Latest report: none');
        expect(request.userMessage).toContain('Latest report context: none');
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toBe('Good morning! I am ready to help.');
    });

    it('does not reuse the latest report finding for fix actions in a fresh chat', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Share the code you want to change.' });
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: vscode.Uri.file('d:\\repo\\src\\app.js'),
                languageId: 'javascript',
                getText: () => 'console.log("hello");',
            },
            selection: { isEmpty: true },
        };
        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        } as any, {
            get: jest.fn((key: string, defaultValue?: unknown) => key === `${PROFILE.storagePrefix}.lastReportSnapshot`
                ? {
                    targetLabel: 'tools/demo',
                    results: [{
                        result: {
                            findings: [{
                                id: 'finding-stale',
                                line: 9,
                                severity: 'HIGH',
                                title: 'Stale finding',
                                explanation: 'Should not be reused after New Chat.',
                                fix: 'Ignore me.',
                            }],
                        },
                    }],
                }
                : defaultValue),
            update: jest.fn(),
        } as any);

        await (provider as any).handleUserMessage('please fix this');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.actions).toBeUndefined();
        const request = complete.mock.calls[0][0];
        expect(request.systemPrompt).toContain('Latest report: none');
        expect(request.userMessage).toContain('Latest report context: none');
    });

    it('adds a Fix code action to scan-backed file results', async () => {
        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete: jest.fn(),
            }),
            allProviders: () => [],
        } as any, {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        } as any);

        (vscode.commands.executeCommand as jest.Mock).mockImplementation(async (command: string, target?: any) => {
            if (command === PROFILE.commands.scanFile) {
                return {
                    uri: target ?? vscode.Uri.file('d:\\repo\\src\\userRepo.js'),
                    result: {
                        score: 6.3,
                        findings: [{
                            id: 'finding-sql',
                            line: 3,
                            lineEnd: 4,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            ruleCode: 'SQ-001',
                            title: 'SQL Injection',
                            explanation: 'Dynamic SQL is built from user input.',
                            threat: 'Data exposure.',
                            fix: 'Use parameterized queries.',
                            confidence: 0.9,
                            provenance: 'ai',
                            likelihood: 'HIGH',
                            riskScore: 9,
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                        durationMs: 10,
                        model: 'owlvex-test-model',
                        provider: 'test-provider',
                        warnings: [],
                        projectContextSummary: 'inline project contract',
                        summary: '1 finding(s) detected.',
                    },
                };
            }

            return undefined;
        });

        await (provider as any).handleUserMessage('scan this file');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Analysis mode: Targeted AI review');
        expect(finalMessage.content).toContain('Analysis mix: targeted_ai: 1');
        expect(finalMessage.content).toContain('Project context: inline project contract');
        expect(finalMessage.content).toContain('Fix first: SQL Injection | via Targeted AI review');
        expect(finalMessage.content).toContain('Next step: use Fix code to open a side-by-side remediation diff.');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix code', kind: 'generateFixPreview', path: 'd:\\repo\\src\\userRepo.js' }),
            expect.objectContaining({ label: 'Explain score', kind: 'explainScore' }),
        ]));
    });

    it('grounds plain fix requests to the latest actionable finding even without latest-report wording', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Use an ownership check.' });
        (vscode.window.activeTextEditor as any) = undefined;
        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        } as any, {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        } as any);

        (provider as any).latestActionableFinding = {
            id: 'finding-idor',
            line: 7,
            lineEnd: 9,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'AC-001',
            title: 'Insecure Direct Object Reference',
            explanation: 'The handler reads a document by id without checking ownership.',
            threat: 'Unauthorized users can read another user document.',
            fix: 'Add object-level authorization.',
            confidence: 0.91,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 9,
            canonicalId: 'owlvex.issue.idor.001',
            canonicalTitle: 'Insecure Direct Object Reference',
        };

        await (provider as any).handleUserMessage('show me how to fix the code');

        const request = complete.mock.calls[0][0];
        expect(request.systemPrompt).toContain('Active finding for follow-up: Insecure Direct Object Reference at line 7');
        expect(request.userMessage).toContain('Finding selected for discussion:');
        expect(request.userMessage).toContain('Title: Insecure Direct Object Reference');
        expect(request.userMessage).toContain('Suggested remediation:');
        expect(request.userMessage).toContain('Latest report context: none');
    });

    it('opens a review diff when the user asks to implement a change for the active finding', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```javascript\nconst safeRedirect = allowList(req.query.next);\nreturn res.redirect(safeRedirect);\n```',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\redirect.js');
        const previewUri = { fsPath: 'untitled:redirect-fix.js', scheme: 'untitled', toString: () => 'untitled:redirect-fix.js' };
        (vscode.window.activeTextEditor as any) = undefined;
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
            if (input?.language === 'javascript') {
                return { uri: previewUri };
            }
            return {
                uri: targetUri,
                languageId: 'javascript',
                getText: () => [
                    'function go(req, res) {',
                    '  return res.redirect(req.query.next);',
                    '}',
                ].join('\n'),
            };
        });

        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [],
        } as any, {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        } as any);

        (provider as any).latestActionableFinding = {
            id: 'finding-open-redirect',
            line: 2,
            lineEnd: 2,
            severity: 'MEDIUM',
            framework: 'OWASP',
            ruleCode: 'A01-REDIRECT',
            title: 'Open Redirect',
            explanation: 'Untrusted destination reaches redirect.',
            threat: 'Phishing.',
            fix: 'Allow-list destinations.',
            confidence: 0.88,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 7,
        };
        (provider as any).latestActionableTargetPath = targetUri.fsPath;

        await (provider as any).handleUserMessage('implement this change in the file');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            'vscode.diff',
            targetUri,
            previewUri,
            expect.stringContaining('Fix Preview - Open Redirect'),
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Keep fix or Discard fix');
    });

    it('injects project context contract into advisory prompts when configured', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Use ownership checks.' });
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: unknown) => {
                switch (key) {
                    case 'frameworks':
                        return ['OWASP', 'STRIDE'];
                    case 'severityThreshold':
                        return 'MEDIUM';
                    case 'projectContext':
                        return 'All document reads must be tenant-scoped.';
                    case 'projectContextFile':
                    case 'teamContext':
                        return '';
                    default:
                        return defaultValue;
                }
            }),
        });
        (vscode.window.activeTextEditor as any) = undefined;

        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        } as any, {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        } as any);

        await (provider as any).handleUserMessage('how should this repo handle document access?');

        const request = complete.mock.calls[0][0];
        expect(request.systemPrompt).toContain('Project context contract available: inline project contract');
        expect(request.userMessage).toContain('Project context contract:');
        expect(request.userMessage).toContain('All document reads must be tenant-scoped.');
    });

    it('runs the project context quick action and reports readiness', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: unknown) => {
                switch (key) {
                    case 'frameworks':
                        return ['OWASP', 'STRIDE'];
                    case 'severityThreshold':
                        return 'MEDIUM';
                    case 'projectContext':
                        return '';
                    case 'projectContextFile':
                        return '.owlvex/project-context.md';
                    case 'teamContext':
                        return '';
                    default:
                        return defaultValue;
                }
            }),
        });

        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete: jest.fn(),
                isConfigured: async () => true,
            }),
            allProviders: () => [],
        } as any, {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        } as any);

        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue(undefined);

        await (provider as any).handleQuickAction('openProjectContext');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(PROFILE.commands.openProjectContext);
        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Project context is ready:');
        expect(finalMessage.content).toContain('.owlvex/project-context.md');
    });

    it('can open a review diff from an action that targets a scanned file path', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: [
                '```js',
                'const safeRedirect = allowList(req.query.next);',
                'return res.redirect(safeRedirect);',
                '```',
            ].join('\n'),
        });
        const provider = new ChatViewProvider({
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [],
        } as any, {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        } as any);

        const targetUri = vscode.Uri.file('d:\\repo\\src\\redirect.js');
        const previewUri = { fsPath: 'untitled:redirect-fix.js', scheme: 'untitled', toString: () => 'untitled:redirect-fix.js' };
        (vscode.window.activeTextEditor as any) = undefined;
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
            if (input?.language === 'javascript') {
                return { uri: previewUri };
            }
            return {
                uri: targetUri,
                languageId: 'javascript',
                getText: () => [
                    'function go(req, res) {',
                    '  return res.redirect(req.query.next);',
                    '}',
                ].join('\n'),
            };
        });

        (provider as any).messages.push({
            role: 'assistant',
            content: 'Scan completed.',
            kind: 'scan',
            actions: [{
                id: 'review-fix-redirect',
                label: 'Fix code',
                kind: 'generateFixPreview',
                path: targetUri.fsPath,
                finding: {
                    id: 'finding-open-redirect',
                    line: 2,
                    lineEnd: 2,
                    severity: 'MEDIUM',
                    framework: 'OWASP',
                    ruleCode: 'A01-REDIRECT',
                    title: 'Open Redirect',
                    explanation: 'Untrusted destination reaches redirect.',
                    threat: 'Phishing.',
                    fix: 'Allow-list destinations.',
                    confidence: 0.88,
                    provenance: 'ai',
                    likelihood: 'HIGH',
                    riskScore: 7,
                },
            }],
        });

        await (provider as any).handleMessageAction((provider as any).messages.length - 1, 'review-fix-redirect');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            'vscode.diff',
            targetUri,
            previewUri,
            expect.stringContaining('Fix Preview - Open Redirect'),
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Keep fix or Discard fix');
    });

    it('applies a generated fix preview only when the file is unchanged', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```js\nconst safe = true;\n```',
        });
        const originalText = 'const safe = false;';
        const targetUri = vscode.Uri.file('d:\\repo\\src\\target.js');
        const previewUri = { fsPath: 'untitled:fix-preview.js', scheme: 'untitled', toString: () => 'untitled:fix-preview.js' };
        const registry = {
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        };
        const storage = {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        };
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: targetUri,
                languageId: 'javascript',
                getText: () => originalText,
            },
            selection: {
                isEmpty: true,
            },
        };
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
            if (input?.language === 'javascript') {
                return { uri: previewUri };
            }
            return {
                uri: targetUri,
                getText: () => originalText,
            };
        });
        (vscode.workspace.applyEdit as jest.Mock).mockResolvedValue(true);
        (vscode.window.showTextDocument as jest.Mock).mockResolvedValue({ revealRange: jest.fn() });
        (vscode.commands.executeCommand as jest.Mock).mockImplementation(async (command: string, target?: any) => {
            if (command === PROFILE.commands.scanFile) {
                return {
                    status: 'completed',
                    uri: target,
                    result: {
                        score: 0,
                        findings: [],
                        positives: [],
                        metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                        durationMs: 10,
                        model: 'owlvex-test-model',
                        provider: 'test-provider',
                        warnings: [],
                        summary: 'No findings detected.',
                    },
                };
            }
            return undefined;
        });

        const provider = new ChatViewProvider(registry as any, storage as any);
        await provider.generateFixPreview({
            id: 'finding-2',
            line: 1,
            lineEnd: 1,
            severity: 'MEDIUM',
            framework: 'OWASP',
            ruleCode: 'GEN-001',
            title: 'Unsafe toggle',
            explanation: 'Unsafe value remains false.',
            threat: 'Unexpected state.',
            fix: 'Set the value safely.',
            confidence: 0.9,
            provenance: 'ai',
            likelihood: 'MEDIUM',
            riskScore: 5,
        } as any);

        await provider.applyPendingFixPreview();

        expect(vscode.workspace.applyEdit).toHaveBeenCalledTimes(1);
        const edit = (vscode.workspace.applyEdit as jest.Mock).mock.calls[0][0];
        expect(edit.entries).toEqual(expect.arrayContaining([
            expect.objectContaining({
                uri: expect.objectContaining({ fsPath: 'd:\\repo\\src\\target.js' }),
                text: 'const safe = true;',
            }),
        ]));
        expect(vscode.window.showTextDocument).toHaveBeenCalledWith(expect.objectContaining({ uri: targetUri }), { preview: false });
        expect(vscode.commands.executeCommand).toHaveBeenNthCalledWith(3, PROFILE.commands.scanFile, expect.objectContaining({ fsPath: 'd:\\repo\\src\\target.js' }));
        expect((provider as any).messages[(provider as any).messages.length - 2].content).toContain('Kept the fix preview');
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Verification: the reviewed finding is no longer present');
        expect((provider as any).pendingFixPreview).toBeUndefined();
    });

    it('opens a source action from a context summary message', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Safe fix' });
        const showTextDocument = jest.fn().mockResolvedValue({ revealRange: jest.fn() });
        (vscode.window.showTextDocument as jest.Mock).mockImplementation(showTextDocument);
        const registry = {
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [{
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            }],
        };
        const storage = {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        };
        const provider = new ChatViewProvider(registry as any, storage as any);
        (provider as any).messages.push({
            role: 'system',
            content: 'Context sources used',
            actions: [{
                id: 'open-active',
                label: 'Open active file',
                kind: 'openSource',
                path: 'd:\\repo\\src\\app.js',
                line: 8,
            }],
        });
        (vscode.workspace.openTextDocument as jest.Mock).mockResolvedValue({
            uri: vscode.Uri.file('d:\\repo\\src\\app.js'),
        });

        await (provider as any).handleMessageAction((provider as any).messages.length - 1, 'open-active');

        expect(vscode.workspace.openTextDocument).toHaveBeenCalledWith(expect.objectContaining({ fsPath: 'd:\\repo\\src\\app.js' }));
        expect(showTextDocument).toHaveBeenCalled();
    });
});
