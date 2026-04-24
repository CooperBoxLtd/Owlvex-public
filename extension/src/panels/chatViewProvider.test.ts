import * as path from 'path';
import * as os from 'os';
import * as vscode from 'vscode';
import * as fs from 'fs/promises';
import { ChatViewProvider, buildFindingContextSummary, buildFindingPromptContext, buildGroundedRemediationHighlights, buildNearbyProjectContext, extractPatchedFileContent, parseChatIntent } from './chatViewProvider';
import { configureRulePackRuntime, resetRulePackRuntime } from '../frameworks/rulePackRegistry';
import { PROFILE } from '../profile';

describe('parseChatIntent', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        resetRulePackRuntime();
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath ?? String(uri));
        (vscode.workspace.workspaceFolders as any) = [];
        (vscode.workspace.fs.readDirectory as jest.Mock).mockResolvedValue([]);
        (vscode.workspace.fs.readFile as jest.Mock).mockReset();
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
                    validation_steps: ['Replay SQL metacharacter payloads.'],
                    unsafe_alternatives: ['Manual quote escaping.'],
                    references: [{
                        label: 'OWASP SQL Injection Prevention Cheat Sheet',
                        kind: 'cheat-sheet',
                        publisher: 'OWASP',
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
        expect(context).toContain('Recommended steps: Replace string-built SQL with placeholders.');
        expect(context).toContain('Validate with: Replay SQL metacharacter payloads.');
        expect(context).toContain('Avoid: Manual quote escaping.');
        expect(context).toContain('Canonical grounding: OWASP SQL Injection Prevention Cheat Sheet');
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

    it('adds an explicit mismatch note when the visible snippet contradicts a deserialization finding label', () => {
        const context = buildFindingPromptContext({
            id: 'finding-deserialization',
            line: 8,
            lineEnd: 8,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'DS-001',
            title: 'Insecure deserialization of untrusted data',
            explanation: 'Untrusted input is deserialized with pickle.',
            threat: 'Remote code execution.',
            fix: 'Use JSON for untrusted input.',
            confidence: 0.92,
            provenance: 'ai',
        } as any, [
            'import json',
            '',
            'def load_profile(request):',
            '    return json.loads(request.body)',
        ].join('\n'));

        expect(context).toContain('Local code snippet:');
        expect(context).toContain('Code/finding note: The visible snippet shows json.loads(...) rather than pickle.loads(...).');
        expect(context).toContain('avoid describing pickle-based code execution unless other grounded context proves it');
    });

    it('starts a fresh chat by default while retaining restorable previous chat state', () => {
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

        expect((provider as any).messages).toEqual([]);
        expect((provider as any).restorableMessages).toEqual([
            { role: 'system', content: 'Owlvex Assistant is ready.', kind: 'advisory' },
            { role: 'user', content: 'Old question' },
            { role: 'assistant', content: 'Old answer', kind: 'advisory' },
        ]);
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
        expect(vscode.commands.executeCommand).toHaveBeenNthCalledWith(1, PROFILE.commands.chatFocus);
        expect(vscode.commands.executeCommand).toHaveBeenNthCalledWith(
            2,
            'vscode.diff',
            expect.anything(),
            expect.objectContaining({ fsPath: expect.stringContaining('owlvex-preview:/') }),
            `${PROFILE.displayLabel}: Fix Preview - SQL Injection`,
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Fix preview ready for');
        expect((provider as any).messages[(provider as any).messages.length - 1].actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Regenerate diff', kind: 'generateFixPreview' }),
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
        expect(request.systemPrompt).toContain('Interaction mode: General');
        expect(request.systemPrompt).toContain('Repo grounding: off by default in General mode.');
        expect(request.userMessage).toContain('Repo context: not injected by default in General mode.');
        expect(request.systemPrompt).toContain('Latest report: none');
        expect(request.userMessage).toContain('Latest report context: none');
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toBe('Good morning! I am ready to help.');
    });

    it('blocks AI chat when no valid licence is available', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'This should not run.' });
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
        } as any, {
            getKey: async () => undefined,
            getCachedInfo: () => null,
            validate: async () => { throw new Error('No licence manager configured.'); },
        } as any);

        await (provider as any).handleUserMessage('explain this vulnerability');

        expect(complete).not.toHaveBeenCalled();
        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('valid Owlvex licence is required');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Use Free', kind: 'quickAction', quickAction: 'useFree' }),
            expect.objectContaining({ label: 'Start Trial', kind: 'quickAction', quickAction: 'startTrial' }),
            expect.objectContaining({ label: 'Enter Licence', kind: 'quickAction', quickAction: 'enterLicence' }),
        ]));
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
        expect(finalMessage.content).toContain('Top issue: SQL Injection | via Targeted AI review');
        expect(finalMessage.content).toContain('Next step: use Fix code to open a side-by-side remediation diff.');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix code', kind: 'generateFixPreview', path: 'd:\\repo\\src\\userRepo.js' }),
            expect.objectContaining({ label: 'Explain score', kind: 'explainScore' }),
        ]));
    });

    it('keeps a single scan-level Fix code action for the latest scan results', async () => {
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

        (vscode.commands.executeCommand as jest.Mock).mockImplementation(async (command: string) => {
            if (command === PROFILE.commands.scanWorkspace) {
                return {
                    status: 'completed',
                    completed: 2,
                    totalFindings: 2,
                    errors: [],
                    results: [
                        {
                            uri: vscode.Uri.file('d:\\repo\\src\\users.js'),
                            result: {
                                score: 9,
                                findings: [{
                                    id: 'finding-users',
                                    line: 5,
                                    lineEnd: 5,
                                    severity: 'HIGH',
                                    framework: 'OWASP',
                                    ruleCode: 'A01-MASS',
                                    title: 'Mass Assignment',
                                    explanation: 'Untrusted body is copied into persisted fields.',
                                    threat: 'Privilege changes.',
                                    fix: 'Allow-list writable fields.',
                                    confidence: 0.93,
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
                                summary: 'Finding in users.js',
                            },
                        },
                        {
                            uri: vscode.Uri.file('d:\\repo\\src\\redirect.js'),
                            result: {
                                score: 7,
                                findings: [{
                                    id: 'finding-redirect',
                                    line: 8,
                                    lineEnd: 8,
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
                                }],
                                positives: [],
                                metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                                durationMs: 12,
                                model: 'owlvex-test-model',
                                provider: 'test-provider',
                                warnings: [],
                                summary: 'Finding in redirect.js',
                            },
                        },
                    ],
                };
            }

            return undefined;
        });

        await (provider as any).handleQuickAction('scanFolder');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        const fixActions = finalMessage.actions.filter((action: any) => action.kind === 'generateFixPreview');
        expect(fixActions).toHaveLength(0);
        const state = (provider as any).buildState([], [], '', '', '', '');
        expect(state.activeModeLabel).toBe('Scan');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix scan broadly', kind: 'generateBatchFixPreview' }),
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
        expect(request.systemPrompt).toContain('Interaction mode: Fix');
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
        (vscode.window.activeTextEditor as any) = undefined;
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
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
            expect.objectContaining({ fsPath: expect.stringContaining('owlvex-preview:/') }),
            expect.stringContaining('Fix Preview - Open Redirect'),
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Choose Keep fix to write the reviewed code into the file');
    });

    it('treats apply changes as a diff preview request instead of a direct save', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```python\nimport json\n\ndef load_profile(request):\n    return json.loads(request.body)\n```',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\tools\\demo\\26-deserialization-unsafe.py');
        (vscode.window.activeTextEditor as any) = undefined;
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
            return {
                uri: targetUri,
                languageId: 'python',
                getText: () => [
                    'import pickle',
                    '',
                    'def load_profile(request):',
                    '    return pickle.loads(request.body)',
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
            id: 'finding-deserialization',
            line: 4,
            lineEnd: 4,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'A08-DESER',
            title: 'Insecure deserialization of untrusted data',
            explanation: 'Untrusted input is deserialized with pickle.',
            threat: 'Remote code execution.',
            fix: 'Use JSON for untrusted input.',
            confidence: 0.92,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 9,
        };
        (provider as any).latestActionableTargetPath = targetUri.fsPath;

        await (provider as any).handleUserMessage('ok apply changes');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            'vscode.diff',
            targetUri,
            expect.objectContaining({ fsPath: expect.stringContaining('owlvex-preview:/') }),
            expect.stringContaining('Fix Preview - Insecure deserialization of untrusted data'),
        );
        expect(vscode.workspace.applyEdit).not.toHaveBeenCalled();
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Choose Keep fix to write the reviewed code into the file');
    });

    it('falls back to grounded local finding context when the provider hits a rate limit', async () => {
        const complete = jest.fn().mockRejectedValue(new Error('Azure Foundry error: 429'));
        const targetUri = vscode.Uri.file('d:\\repo\\src\\deser.py');

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
            id: 'finding-deserialization',
            line: 4,
            lineEnd: 4,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'A08-DESER',
            title: 'Insecure deserialization of untrusted data',
            explanation: 'Untrusted input is deserialized with pickle.',
            threat: 'An attacker can craft a malicious payload that executes during deserialization.',
            fix: 'Use JSON for untrusted input and validate the payload shape.',
            confidence: 0.92,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 9,
        };
        (provider as any).latestActionableTargetPath = targetUri.fsPath;

        await (provider as any).handleUserMessage('ok explain me how this vulnerability can be exploited');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('falling back to grounded local context');
        expect(finalMessage.content).toContain('How it can be abused: An attacker can craft a malicious payload');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix code', kind: 'generateFixPreview', path: targetUri.fsPath }),
        ]));
    });

    it('falls back to grounded local finding context for follow-up explanation prompts when the provider fails', async () => {
        const complete = jest.fn().mockRejectedValue(new Error('temporary upstream failure'));
        const targetUri = vscode.Uri.file('d:\\repo\\src\\ssrf.js');

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
            id: 'finding-ssrf',
            line: 7,
            lineEnd: 7,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'A10-SSRF',
            title: 'Server-side request forgery through untrusted destination',
            explanation: 'The handler fetches a user-controlled destination.',
            threat: 'An attacker can force the server to reach internal services or attacker-controlled hosts.',
            fix: 'Allow only approved outbound hosts and block redirects to untrusted destinations.',
            confidence: 0.93,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 9,
        };
        (provider as any).latestActionableTargetPath = targetUri.fsPath;

        await (provider as any).handleUserMessage('explain findings');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('falling back to grounded local context');
        expect(finalMessage.content).toContain('What is wrong: The handler fetches a user-controlled destination.');
        expect(finalMessage.content).not.toContain('Request failed: temporary upstream failure');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix code', kind: 'generateFixPreview', path: targetUri.fsPath }),
        ]));
    });

    it('keeps Fix code available after an explanation follow-up for the active finding', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: 'This issue lets user input control the redirect destination without validation.',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\redirect.js');

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

        await (provider as any).handleUserMessage('explain findings');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('redirect destination');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix code', kind: 'generateFixPreview', path: targetUri.fsPath }),
        ]));
    });

    it('allows free-plan assistant chat when the licence is valid', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: 'Free can still use the assistant.',
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
        } as any, {
            getKey: async () => 'owlvex_lic_FREE_DEV_SEED',
            getCachedInfo: () => ({
                valid: true,
                licenceId: 'lic-free',
                teamName: 'Free Dev',
                plan: 'free',
                seats: 1,
                seatsUsed: 0,
                features: {
                    frameworks: ['OWASP'],
                    scansPerMonth: 50,
                    promptEditor: true,
                    comparison: true,
                    teamPrompts: false,
                    ciCd: false,
                    pdfReports: false,
                    customRules: false,
                    sso: false,
                    industryPacks: [],
                },
                expiresAt: null,
            }),
            validate: async () => { throw new Error('should not validate when cached info exists'); },
        } as any);

        await (provider as any).handleUserMessage('help me fix this vulnerability');

        expect(complete).toHaveBeenCalled();
        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Free can still use the assistant.');
    });

    it('keeps Keep fix and Discard fix visible during diff-focused follow-ups', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: 'The preview is replacing the unsafe redirect with an allow-listed destination.',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\redirect.js');

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

        const finding = {
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
        (provider as any).latestActionableFinding = finding;
        (provider as any).latestActionableTargetPath = targetUri.fsPath;
        (provider as any).pendingFixPreview = {
            targetPath: targetUri.fsPath,
            originalText: 'return res.redirect(req.query.next);',
            patchedText: 'return res.redirect(allowList(req.query.next));',
            finding,
        };

        await (provider as any).handleUserMessage('show me');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('allow-listed destination');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Regenerate diff', kind: 'generateFixPreview' }),
            expect.objectContaining({ label: 'Keep fix', kind: 'applyFixPreview' }),
            expect.objectContaining({ label: 'Discard fix', kind: 'discardFixPreview' }),
        ]));
    });

    it('keeps the active fix target after discarding a preview so the user can regenerate it', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```javascript\nconst safeRedirect = allowList(req.query.next);\nreturn res.redirect(safeRedirect);\n```',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\redirect.js');
        (vscode.window.activeTextEditor as any) = undefined;
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
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

        await (provider as any).handleUserMessage('fix this');
        await (provider as any).handleMessageAction((provider as any).messages.length - 1, 'discard-fix-preview');
        await (provider as any).handleUserMessage('do it');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            'vscode.diff',
            targetUri,
            expect.objectContaining({ fsPath: expect.stringContaining('owlvex-preview:/') }),
            expect.stringContaining('Fix Preview - Open Redirect'),
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Choose Keep fix to write the reviewed code into the file');
    });

    it('keeps regenerate diff available during a pending fix preview', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: 'Preview explanation.',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\redirect.js');
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

        const finding = {
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
        (provider as any).latestActionableFinding = finding;
        (provider as any).latestActionableTargetPath = targetUri.fsPath;
        (provider as any).latestActionableItems = [{ finding, targetPath: targetUri.fsPath }];
        (provider as any).pendingFixPreview = {
            targetPath: targetUri.fsPath,
            originalText: 'return res.redirect(req.query.next);',
            patchedText: 'return res.redirect(allowList(req.query.next));',
            finding,
        };

        await (provider as any).handleUserMessage('fix code');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Regenerate diff', kind: 'generateFixPreview' }),
            expect.objectContaining({ label: 'Keep fix', kind: 'applyFixPreview' }),
            expect.objectContaining({ label: 'Discard fix', kind: 'discardFixPreview' }),
        ]));
    });

    it('keeps the active fix target when fix preview generation fails so the user can retry', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```javascript\nfunction go(req, res) {\n  return res.redirect(req.query.next);\n}\n```',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\redirect.js');
        (vscode.window.activeTextEditor as any) = undefined;
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async () => ({
            uri: targetUri,
            languageId: 'javascript',
            getText: () => [
                'function go(req, res) {',
                '  return res.redirect(req.query.next);',
                '}',
            ].join('\n'),
        }));

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

        const finding = {
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

        (provider as any).latestActionableFinding = finding;
        (provider as any).latestActionableTargetPath = targetUri.fsPath;

        await provider.generateFixPreview(finding as any, targetUri.fsPath);

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Fix preview failed');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix code', kind: 'generateFixPreview', path: targetUri.fsPath }),
        ]));
        expect((provider as any).latestActionableTargetPath).toBe(targetUri.fsPath);
        expect((provider as any).pendingFixPreview).toBeUndefined();
        expect(vscode.commands.executeCommand).not.toHaveBeenCalledWith(
            'vscode.diff',
            expect.anything(),
            expect.anything(),
            expect.stringContaining('Fix Preview - Open Redirect'),
        );
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
        expect(request.systemPrompt).toContain('Interaction mode: Repo Q&A');
        expect(request.systemPrompt).toContain('Project context contract available: inline project contract');
        expect(request.userMessage).toContain('Project context contract:');
        expect(request.userMessage).toContain('All document reads must be tenant-scoped.');
    });

    it('uses workspace repo context when the working scope is workspace', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'This looks like a small Node test app.' });
        (vscode.workspace.workspaceFolders as any) = [{ name: 'demo-app', uri: vscode.Uri.file('d:\\repo') }];
        (vscode.workspace.fs as any).readDirectory = jest.fn().mockResolvedValue([
            ['README.md', vscode.FileType.File],
            ['package.json', vscode.FileType.File],
            ['src', vscode.FileType.Directory],
        ]);
        (vscode.workspace.fs.readFile as jest.Mock).mockImplementation(async (uri: any) => {
            const filePath = String(uri.fsPath);
            if (filePath.endsWith('README.md')) {
                return Buffer.from('# Demo App\nA small API used for benchmark testing.');
            }
            if (filePath.endsWith('package.json')) {
                return Buffer.from(JSON.stringify({ name: 'demo-app', scripts: { start: 'node src/server.js' } }, null, 2));
            }
            throw new Error('not found');
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
            get: jest.fn((key: string, defaultValue?: unknown) => {
                if (key === `${PROFILE.storagePrefix}.chat.workingScope`) {
                    return 'scanFolder';
                }
                return defaultValue;
            }),
            update: jest.fn(),
        } as any);

        await (provider as any).handleUserMessage('what is this app doing?');

        const request = complete.mock.calls[0][0];
        expect(request.systemPrompt).toContain('Working scope: Workspace');
        expect(request.userMessage).toContain('Working scope: Workspace');
        expect(request.userMessage).toContain('Project root: d:\\repo');
        expect(request.userMessage).toContain('README.md:');
        expect(request.userMessage).toContain('package.json:');
    });

    it('rejects overbroad single-file rewrites during fix preview generation', async () => {
        const targetUri = vscode.Uri.file('d:\\repo\\src\\service.js');
        const originalText = Array.from({ length: 24 }, (_, index) => `const line${index + 1} = ${index + 1};`).join('\n');
        const replacementText = Array.from({ length: 24 }, (_, index) => `const rewritten${index + 1} = secure(${index + 1});`).join('\n');
        const complete = jest.fn().mockResolvedValue({
            content: `\`\`\`javascript\n${replacementText}\n\`\`\``,
        });

        (vscode.workspace.openTextDocument as jest.Mock).mockResolvedValue({
            uri: targetUri,
            getText: () => originalText,
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

        await provider.generateFixPreview({
            id: 'finding-broad-rewrite',
            line: 10,
            lineEnd: 10,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'GEN-001',
            title: 'Unsafe command execution',
            explanation: 'User input reaches a shell sink.',
            threat: 'Command execution.',
            fix: 'Use execFile with explicit arguments.',
            confidence: 0.9,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 9,
        } as any, targetUri.fsPath);

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('rewrote too much of the file');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Fix code', kind: 'generateFixPreview', path: targetUri.fsPath }),
        ]));
        expect(vscode.commands.executeCommand).not.toHaveBeenCalledWith(
            'vscode.diff',
            expect.anything(),
            expect.anything(),
            expect.stringContaining('Fix Preview'),
        );
    });

    it('prefers a targeted repo module when the repo question names it', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'The demo app is a small Express app with paired safe and unsafe routes.' });
        (vscode.workspace.workspaceFolders as any) = [{ name: 'CodeScanner', uri: vscode.Uri.file('d:\\repo') }];
        (vscode.workspace.fs as any).readDirectory = jest.fn().mockImplementation(async (uri: any) => {
            const filePath = String(uri.fsPath).toLowerCase();
            if (filePath === 'd:\\repo') {
                return [
                    ['tools', vscode.FileType.Directory],
                    ['docs', vscode.FileType.Directory],
                    ['README.md', vscode.FileType.File],
                ];
            }
            if (filePath === 'd:\\repo\\tools') {
                return [
                    ['demo-app', vscode.FileType.Directory],
                    ['demo', vscode.FileType.Directory],
                ];
            }
            if (filePath === 'd:\\repo\\tools\\demo-app') {
                return [
                    ['README.md', vscode.FileType.File],
                    ['package.json', vscode.FileType.File],
                    ['src', vscode.FileType.Directory],
                ];
            }
            if (filePath === 'd:\\repo\\docs' || filePath === 'd:\\repo\\tools\\demo') {
                return [];
            }
            if (filePath === 'd:\\repo\\tools\\demo-app\\src') {
                return [
                    ['server.js', vscode.FileType.File],
                ];
            }
            return [];
        });
        (vscode.workspace.fs.readFile as jest.Mock).mockImplementation(async (uri: any) => {
            const filePath = String(uri.fsPath).toLowerCase();
            if (filePath.endsWith('tools\\demo-app\\readme.md')) {
                return Buffer.from('# Owlvex Demo App\nA small intentionally vulnerable training app for repo-context validation.');
            }
            if (filePath.endsWith('tools\\demo-app\\package.json')) {
                return Buffer.from(JSON.stringify({ name: 'owlvex-demo-app', main: 'src/server.js' }, null, 2));
            }
            if (filePath.endsWith('tools\\demo-app\\src\\server.js')) {
                return Buffer.from("const express = require('express');\napp.use('/documents', documentRoutes);");
            }
            throw new Error('not found');
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
            get: jest.fn((key: string, defaultValue?: unknown) => {
                if (key === `${PROFILE.storagePrefix}.chat.workingScope`) {
                    return 'scanFolder';
                }
                return defaultValue;
            }),
            update: jest.fn(),
        } as any);

        await (provider as any).handleUserMessage('what is the demo app supposed to do?');

        const request = complete.mock.calls[0][0];
        expect(request.systemPrompt).toContain('Interaction mode: Repo Q&A');
        expect(request.userMessage).toContain('Targeted repo focus: tools/demo-app');
        expect(request.userMessage).toContain('Module path: tools/demo-app');
        expect(request.userMessage).toContain('tools/demo-app');
        expect(request.userMessage).toContain('src/server.js:');
        expect(request.userMessage).toContain('Owlvex may use the full selected project root as context, but should keep this targeted module as the primary interpretation target.');
        expect(request.userMessage).not.toContain('Workspace folder: CodeScanner');
    });

    it('keeps repo overview out of chat prompts when the working scope is current file', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'This file looks like a route.' });
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: vscode.Uri.file('d:\\repo\\src\\app.js'),
                languageId: 'javascript',
                getText: () => 'export function run() { return true; }',
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
            allProviders: () => [],
        } as any, {
            get: jest.fn((key: string, defaultValue?: unknown) => {
                if (key === `${PROFILE.storagePrefix}.chat.workingScope`) {
                    return 'scanFile';
                }
                return defaultValue;
            }),
            update: jest.fn(),
        } as any);

        await (provider as any).handleUserMessage('what is this app doing?');

        const request = complete.mock.calls[0][0];
        expect(request.systemPrompt).toContain('Working scope: Current file');
        expect(request.userMessage).toContain('Active file: d:\\repo\\src\\app.js');
        expect(request.userMessage).not.toContain('Workspace folder:');
        expect(request.userMessage).not.toContain('README.md:');
    });

    it('allows combined fix previews when the findings span different families', async () => {
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (uri: any) => ({
            uri,
            fileName: uri.fsPath,
            getText: () => uri.fsPath.endsWith('one.js')
                ? 'db.query(req.query.id);'
                : 'fetch(req.query.url);',
        }));
        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue(undefined);

        const complete = jest.fn()
            .mockResolvedValueOnce({ content: 'const id = Number(req.query.id);\ndb.query(id);' })
            .mockResolvedValueOnce({ content: 'const target = allowlisted(req.query.url);\nfetch(target);' });
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

        await provider.generateBatchFixPreview([
            {
                targetPath: 'd:\\repo\\src\\one.js',
                finding: {
                    id: 'finding-sqli',
                    line: 3,
                    lineEnd: 3,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'SQ-001',
                    title: 'SQL Injection',
                    canonicalId: 'owlvex.issue.sql_injection.001',
                    explanation: 'Unsafe SQL.',
                    threat: 'Data exposure.',
                    fix: 'Use parameters.',
                    confidence: 0.9,
                    provenance: 'ai',
                    likelihood: 'HIGH',
                    riskScore: 9,
                },
            },
            {
                targetPath: 'd:\\repo\\src\\two.js',
                finding: {
                    id: 'finding-ssrf',
                    line: 4,
                    lineEnd: 4,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'GR-003',
                    title: 'SSRF',
                    canonicalId: 'owlvex.issue.ssrf.001',
                    explanation: 'Unsafe outbound request.',
                    threat: 'Internal network reachability.',
                    fix: 'Allow-list destinations.',
                    confidence: 0.9,
                    provenance: 'ai',
                    likelihood: 'HIGH',
                    riskScore: 9,
                },
            },
        ] as any);

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Fix preview ready for 2 files.');
        expect(complete).toHaveBeenCalledTimes(2);
        expect((provider as any).pendingFixPreview?.changes).toHaveLength(2);
    });

    it('rescans each file after applying a combined fix preview', async () => {
        const originals = new Map([
            ['d:\\repo\\src\\one.js', 'db.query(req.query.id);'],
            ['d:\\repo\\src\\two.js', 'fetch(req.query.url);'],
        ]);
        const patched = new Map([
            ['d:\\repo\\src\\one.js', 'const id = Number(req.query.id);\ndb.query(id);'],
            ['d:\\repo\\src\\two.js', 'const target = allowlisted(req.query.url);\nfetch(target);'],
        ]);
        let applied = false;

        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (uri: any) => ({
            uri,
            fileName: uri.fsPath,
            getText: () => applied
                ? patched.get(uri.fsPath) ?? originals.get(uri.fsPath) ?? ''
                : originals.get(uri.fsPath) ?? '',
        }));
        (vscode.workspace.applyEdit as jest.Mock).mockImplementation(async () => {
            applied = true;
            return true;
        });
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

        const complete = jest.fn()
            .mockResolvedValueOnce({ content: patched.get('d:\\repo\\src\\one.js') })
            .mockResolvedValueOnce({ content: patched.get('d:\\repo\\src\\two.js') });
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

        await provider.generateBatchFixPreview([
            {
                targetPath: 'd:\\repo\\src\\one.js',
                finding: {
                    id: 'finding-sqli',
                    line: 3,
                    lineEnd: 3,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'SQ-001',
                    title: 'SQL Injection',
                    canonicalId: 'owlvex.issue.sql_injection.001',
                    explanation: 'Unsafe SQL.',
                    threat: 'Data exposure.',
                    fix: 'Use parameters.',
                    confidence: 0.9,
                    provenance: 'ai',
                    likelihood: 'HIGH',
                    riskScore: 9,
                },
            },
            {
                targetPath: 'd:\\repo\\src\\two.js',
                finding: {
                    id: 'finding-ssrf',
                    line: 4,
                    lineEnd: 4,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'GR-003',
                    title: 'SSRF',
                    canonicalId: 'owlvex.issue.ssrf.001',
                    explanation: 'Unsafe outbound request.',
                    threat: 'Internal network reachability.',
                    fix: 'Allow-list destinations.',
                    confidence: 0.9,
                    provenance: 'ai',
                    likelihood: 'HIGH',
                    riskScore: 9,
                },
            },
        ] as any);

        await provider.applyPendingFixPreview();

        expect(vscode.workspace.applyEdit).toHaveBeenCalledTimes(1);
        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            PROFILE.commands.scanFile,
            expect.objectContaining({ fsPath: 'd:\\repo\\src\\one.js' }),
        );
        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            PROFILE.commands.scanFile,
            expect.objectContaining({ fsPath: 'd:\\repo\\src\\two.js' }),
        );
        expect((provider as any).messages.map((message: any) => message.content).join('\n')).toContain('Verifying the 2 updated files now');
        expect((provider as any).messages.map((message: any) => message.content).join('\n')).toContain('Verification complete: the reviewed finding is no longer present');
    });

    it('allows broader rewrites for latest-scan batch fixes without tripping the finding-anchored guardrail', async () => {
        const targetUri = vscode.Uri.file('d:\\repo\\src\\sessionHost.js');
        const originalLines = Array.from({ length: 40 }, (_, index) => `const line${index + 1} = ${index + 1};`).join('\n');
        const rewrittenLines = Array.from({ length: 40 }, (_, index) => `const safeLine${index + 1} = ${index + 1};`).join('\n');

        (vscode.workspace.openTextDocument as jest.Mock).mockResolvedValue({
            uri: targetUri,
            fileName: targetUri.fsPath,
            getText: () => originalLines,
        });
        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue(undefined);

        const complete = jest.fn().mockResolvedValue({ content: rewrittenLines });
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

        await provider.generateBatchFixPreview([
            {
                targetPath: targetUri.fsPath,
                finding: {
                    id: 'finding-host-lock',
                    line: 10,
                    lineEnd: 28,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'AC-001',
                    title: 'Peer-controlled lock ownership',
                    canonicalId: 'owlvex.issue.access_control.001',
                    explanation: 'Peer identity controls lock ownership.',
                    threat: 'Authorization bypass.',
                    fix: 'Bind lock ownership to the server-side session.',
                    confidence: 0.9,
                    provenance: 'ai',
                    likelihood: 'HIGH',
                    riskScore: 9,
                },
            },
        ] as any);

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Fix preview ready for 1 file.');
        expect(finalMessage.content).not.toContain('rewrote too much of the file');
        expect((provider as any).pendingFixPreview?.changes).toHaveLength(1);
        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            'vscode.diff',
            expect.anything(),
            expect.anything(),
            expect.stringContaining('Fix Preview - Latest Scan'),
        );
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
        (vscode.window.activeTextEditor as any) = undefined;
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
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
            expect.objectContaining({ fsPath: expect.stringContaining('owlvex-preview:/') }),
            expect.stringContaining('Fix Preview - Open Redirect'),
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Choose Keep fix to write the reviewed code into the file');
    });

    it('applies a generated fix preview only when the file is unchanged', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```js\nconst safe = true;\n```',
        });
        const originalText = 'const safe = false;';
        const targetUri = vscode.Uri.file('d:\\repo\\src\\target.js');
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
        expect((provider as any).messages[(provider as any).messages.length - 2].content).toContain('Kept the reviewed fix');
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Verification complete: the reviewed finding is no longer present');
        expect((provider as any).messages[(provider as any).messages.length - 1].actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Explain score', kind: 'explainScore' }),
            expect.objectContaining({ label: 'Scan current file', kind: 'quickAction', quickAction: 'scanFile' }),
            expect.objectContaining({ label: 'Scan workspace', kind: 'quickAction', quickAction: 'scanFolder' }),
        ]));
        expect((provider as any).pendingFixPreview).toBeUndefined();
    });

    it('records a fix benchmark result automatically for matching benchmark files after verification', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```javascript\nconst query = db.query(\"SELECT * FROM users WHERE id = ?\", [req.query.id]);\n```',
        });
        const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'owlvex-fix-benchmark-'));
        const benchmarkDir = path.join(tempRoot, 'tools', 'fix-benchmark');
        await fs.mkdir(benchmarkDir, { recursive: true });
        await fs.writeFile(
            path.join(benchmarkDir, 'fix-benchmark.expectations.json'),
            JSON.stringify({
                name: 'owlvex-fix-demo-benchmark',
                expectations: [
                    { caseId: 'FIX-SQ-001', file: 'tools/demo/06-sqli-unsafe.js' },
                ],
            }, null, 2),
            'utf8',
        );
        const targetUri = vscode.Uri.file(path.join(tempRoot, 'tools', 'demo', '06-sqli-unsafe.js'));
        const originalText = 'const query = "SELECT * FROM users WHERE id = " + req.query.id;';
        (vscode.workspace.workspaceFolders as any) = [{ name: 'CodeScanner', uri: vscode.Uri.file(tempRoot) }];
        (vscode.workspace.getWorkspaceFolder as jest.Mock).mockReturnValue({ name: 'CodeScanner', uri: vscode.Uri.file(tempRoot) });
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (input: any) => {
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

        const registry = {
            getActive: () => ({
                id: 'test-provider',
                name: 'Test Provider',
                selectedModel: 'owlvex-test-model',
                complete,
            }),
            allProviders: () => [({
                id: 'test-provider',
                name: 'Test Provider',
                isConfigured: async () => true,
                listModels: async () => ['owlvex-test-model'],
            })],
        };
        const storage = {
            get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
            update: jest.fn(),
        };

        const provider = new ChatViewProvider(registry as any, storage as any);
        await provider.generateFixPreview({
            id: 'finding-sqli',
            line: 1,
            lineEnd: 1,
            severity: 'HIGH',
            framework: 'OWASP',
            ruleCode: 'SQ-001',
            title: 'SQL Injection',
            explanation: 'Untrusted request data is concatenated into SQL.',
            threat: 'Attackers can alter database queries.',
            fix: 'Use parameterized queries.',
            confidence: 0.95,
            provenance: 'ai',
            likelihood: 'HIGH',
            riskScore: 9,
            canonicalId: 'owlvex.issue.sql_injection.001',
            canonicalTitle: 'SQL Injection',
        } as any, targetUri.fsPath);

        await provider.applyPendingFixPreview();

        const resultsPath = path.join(benchmarkDir, 'fix-benchmark.latest.json');
        const parsed = JSON.parse(await fs.readFile(resultsPath, 'utf8'));
        expect(parsed.benchmark).toBe('owlvex-fix-demo-benchmark');
        expect(parsed.runs).toEqual(expect.arrayContaining([
            expect.objectContaining({
                caseId: 'FIX-SQ-001',
                attempted: true,
                previewGenerated: true,
                appliedCleanly: true,
                filesChanged: ['tools/demo/06-sqli-unsafe.js'],
                syntaxValid: true,
                targetFindingRemoved: true,
                introducedHighRiskFindings: false,
            }),
        ]));
        await fs.rm(tempRoot, { recursive: true, force: true });
    });

    it('treats rescanned deserialization findings as the same family when titles differ only by casing', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```python\nimport pickle\n\ndef load_profile(request):\n    return pickle.loads(request.body)\n```',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\tools\\demo\\26-deserialization-unsafe.py');
        const originalText = 'import pickle\n\ndef load_profile(request):\n    return pickle.loads(request.body)\n';
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

        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async () => ({
            uri: targetUri,
            getText: () => originalText,
        }));
        (vscode.workspace.applyEdit as jest.Mock).mockResolvedValue(true);
        (vscode.window.showTextDocument as jest.Mock).mockResolvedValue({ revealRange: jest.fn() });
        (vscode.commands.executeCommand as jest.Mock).mockImplementation(async (command: string, target?: any) => {
            if (command === PROFILE.commands.scanFile) {
                return {
                    status: 'completed',
                    uri: target,
                    result: {
                        score: 9,
                        findings: [{
                            id: 'rescanned-deser',
                            line: 4,
                            lineEnd: 4,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            ruleCode: 'DS-001',
                            title: 'Insecure Deserialization',
                            canonicalId: 'owlvex.issue.insecure_deserialization.001',
                            canonicalTitle: 'Insecure Deserialization',
                            explanation: 'The request body is passed into pickle.loads.',
                            threat: 'Attackers can trigger unsafe object loading.',
                            fix: 'Replace pickle with a data-only format.',
                            confidence: 1,
                            provenance: 'deterministic',
                            likelihood: 'HIGH',
                            riskScore: 9,
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                        durationMs: 10,
                        model: 'owlvex-test-model',
                        provider: 'test-provider',
                        warnings: [],
                        summary: '1 finding detected.',
                    },
                };
            }
            return undefined;
        });

        const provider = new ChatViewProvider(registry as any, storage as any);
        (provider as any).pendingFixPreview = {
            targetPath: targetUri.fsPath,
            originalText,
            patchedText: originalText,
            title: 'Insecure deserialization',
            reviewedPaths: [targetUri.fsPath],
            finding: {
                id: 'ai-deser',
                line: 4,
                lineEnd: 4,
                severity: 'HIGH',
                framework: 'OWASP',
                ruleCode: 'A08-DESER',
                title: 'Insecure deserialization',
                explanation: 'A pickle payload from the request is deserialized directly.',
                threat: 'Attackers can trigger malicious object materialization.',
                fix: 'Replace unsafe deserialization with safe parsing.',
                confidence: 0.81,
                provenance: 'ai',
                likelihood: 'HIGH',
                riskScore: 9,
            },
        };

        await provider.applyPendingFixPreview();

        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain(
            'Verification complete: the finding is still present after the kept fix.',
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Regenerate diff', kind: 'generateFixPreview' }),
            expect.objectContaining({ label: 'Explain score', kind: 'explainScore' }),
            expect.objectContaining({ label: 'Scan current file', kind: 'quickAction', quickAction: 'scanFile' }),
        ]));
    });

    it('treats the same finding family on a different rescanned line as still present', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```javascript\nconst query = db.query(sql, [req.query.id]);\n```',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\target.js');
        const originalText = 'const query = "SELECT * FROM users WHERE id = " + req.query.id;';
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

        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async () => ({
            uri: targetUri,
            getText: () => originalText,
        }));
        (vscode.workspace.applyEdit as jest.Mock).mockResolvedValue(true);
        (vscode.window.showTextDocument as jest.Mock).mockResolvedValue({ revealRange: jest.fn() });
        (vscode.commands.executeCommand as jest.Mock).mockImplementation(async (command: string, target?: any) => {
            if (command === PROFILE.commands.scanFile) {
                return {
                    status: 'completed',
                    uri: target,
                    result: {
                        score: 9,
                        findings: [{
                            id: 'rescanned-sqli',
                            line: 5,
                            lineEnd: 5,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            ruleCode: 'SQ-001',
                            title: 'SQL Injection',
                            canonicalId: 'owlvex.issue.sql_injection.001',
                            canonicalTitle: 'SQL Injection',
                            explanation: 'Untrusted input still reaches the SQL sink.',
                            threat: 'Attackers can alter database queries.',
                            fix: 'Use parameterized queries.',
                            confidence: 1,
                            provenance: 'deterministic',
                            likelihood: 'HIGH',
                            riskScore: 9,
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                        durationMs: 10,
                        model: 'owlvex-test-model',
                        provider: 'test-provider',
                        warnings: [],
                        summary: '1 finding detected.',
                    },
                };
            }
            return undefined;
        });

        const provider = new ChatViewProvider(registry as any, storage as any);
        (provider as any).pendingFixPreview = {
            targetPath: targetUri.fsPath,
            originalText,
            patchedText: originalText,
            title: 'SQL Injection',
            reviewedPaths: [targetUri.fsPath],
            finding: {
                id: 'ai-sqli',
                line: 1,
                lineEnd: 1,
                severity: 'HIGH',
                framework: 'OWASP',
                ruleCode: 'A03-SQL',
                title: 'SQL Injection',
                explanation: 'Untrusted request data is concatenated into SQL.',
                threat: 'Attackers can alter database queries.',
                fix: 'Use parameterized queries.',
                confidence: 0.95,
                provenance: 'ai',
                likelihood: 'HIGH',
                riskScore: 9,
                canonicalId: 'owlvex.issue.sql_injection.001',
                canonicalTitle: 'SQL Injection',
            },
        };

        await provider.applyPendingFixPreview();

        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain(
            'Verification complete: the finding is still present after the kept fix.',
        );
    });

    it('reports risk reduction when the rescanned finding family remains but with lower risk', async () => {
        const complete = jest.fn().mockResolvedValue({
            content: '```javascript\nconst query = db.query(sql, [req.query.id]);\n```',
        });
        const targetUri = vscode.Uri.file('d:\\repo\\src\\target.js');
        const originalText = 'const query = "SELECT * FROM users WHERE id = " + req.query.id;';
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

        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async () => ({
            uri: targetUri,
            getText: () => originalText,
        }));
        (vscode.workspace.applyEdit as jest.Mock).mockResolvedValue(true);
        (vscode.window.showTextDocument as jest.Mock).mockResolvedValue({ revealRange: jest.fn() });
        (vscode.commands.executeCommand as jest.Mock).mockImplementation(async (command: string, target?: any) => {
            if (command === PROFILE.commands.scanFile) {
                return {
                    status: 'completed',
                    uri: target,
                    result: {
                        score: 7,
                        findings: [{
                            id: 'rescanned-sqli-lower-risk',
                            line: 1,
                            lineEnd: 1,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            ruleCode: 'SQ-001',
                            title: 'SQL Injection',
                            canonicalId: 'owlvex.issue.sql_injection.001',
                            canonicalTitle: 'SQL Injection',
                            explanation: 'The query construction remains risky but the sink is partially constrained.',
                            threat: 'Attackers may still influence the query.',
                            fix: 'Use parameterized queries.',
                            confidence: 1,
                            provenance: 'deterministic',
                            likelihood: 'HIGH',
                            riskScore: 7,
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                        durationMs: 10,
                        model: 'owlvex-test-model',
                        provider: 'test-provider',
                        warnings: [],
                        summary: '1 finding detected.',
                    },
                };
            }
            return undefined;
        });

        const provider = new ChatViewProvider(registry as any, storage as any);
        (provider as any).pendingFixPreview = {
            targetPath: targetUri.fsPath,
            originalText,
            patchedText: originalText,
            title: 'SQL Injection',
            reviewedPaths: [targetUri.fsPath],
            finding: {
                id: 'ai-sqli',
                line: 1,
                lineEnd: 1,
                severity: 'HIGH',
                framework: 'OWASP',
                ruleCode: 'A03-SQL',
                title: 'SQL Injection',
                explanation: 'Untrusted request data is concatenated into SQL.',
                threat: 'Attackers can alter database queries.',
                fix: 'Use parameterized queries.',
                confidence: 0.95,
                provenance: 'ai',
                likelihood: 'HIGH',
                riskScore: 9,
                canonicalId: 'owlvex.issue.sql_injection.001',
                canonicalTitle: 'SQL Injection',
            },
        };

        await provider.applyPendingFixPreview();

        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain(
            'Verification complete: the finding still exists, but its risk dropped from 9/10 to 7/10.',
        );
        expect((provider as any).messages[(provider as any).messages.length - 1].actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Regenerate diff', kind: 'generateFixPreview' }),
            expect.objectContaining({ label: 'Explain score', kind: 'explainScore' }),
            expect.objectContaining({ label: 'Scan workspace', kind: 'quickAction', quickAction: 'scanFolder' }),
        ]));
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

    it('blocks applying a fix preview when the reviewed file scope does not match the preview target', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Safe fix' });
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
        (provider as any).pendingFixPreview = {
            targetPath: 'd:\\repo\\src\\target.js',
            originalText: 'const safe = false;',
            patchedText: 'const safe = true;',
            title: 'Unsafe toggle',
            reviewedPaths: ['d:\\repo\\src\\other.js'],
            finding: {
                id: 'finding-3',
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
            },
        };

        await provider.applyPendingFixPreview();

        expect(vscode.workspace.applyEdit).not.toHaveBeenCalled();
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('reviewed file scope no longer matches');
        expect((provider as any).pendingFixPreview).toBeUndefined();
    });

    it('shows the security boundary summary from settings quick actions', async () => {
        const complete = jest.fn().mockResolvedValue({ content: 'Safe fix' });
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

        await (provider as any).handleQuickAction('securityBoundary');

        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Owlvex security boundary:');
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Deterministic scanning runs locally');
        expect((provider as any).messages[(provider as any).messages.length - 1].content).toContain('Fixes stay in preview until you choose Keep fix');
    });

    it('shows a plan overview from settings quick actions', async () => {
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

        await (provider as any).handleQuickAction('viewPlans');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Owlvex plans:');
        expect(finalMessage.content).toContain('Free: register and verify your email');
        expect(finalMessage.content).toContain('Developer: full individual workflow');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Use Free', kind: 'quickAction', quickAction: 'useFree' }),
            expect.objectContaining({ label: 'Start Trial', kind: 'quickAction', quickAction: 'startTrial' }),
            expect.objectContaining({ label: 'Enter Licence', kind: 'quickAction', quickAction: 'enterLicence' }),
        ]));
    });

    it('shows an onboarding checklist with next actions based on live setup state', async () => {
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

        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue({
            status: 'needs_attention',
            backend: true,
            licence: false,
            provider: false,
            summary: [
                'Backend: reachable (42ms)',
                'Licence: No licence key entered yet.',
                'LLM: Test Provider is not configured yet.',
            ],
        });

        await (provider as any).handleQuickAction('showOnboarding');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(PROFILE.commands.testTrialSetup);
        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Owlvex onboarding checklist:');
        expect(finalMessage.content).toContain('Backend connection: ready');
        expect(finalMessage.content).toContain('Licence or registration: needs setup');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Use Free', kind: 'quickAction', quickAction: 'useFree' }),
            expect.objectContaining({ label: 'Start Trial', kind: 'quickAction', quickAction: 'startTrial' }),
            expect.objectContaining({ label: 'Configure LLM', kind: 'quickAction', quickAction: 'setupAI' }),
        ]));
    });

    it('shows trial onboarding guidance when no active trial is cached', async () => {
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
        } as any, {
            getKey: async () => undefined,
            getCachedInfo: () => null,
            validate: async () => { throw new Error('no validation expected'); },
        } as any);

        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue(undefined);

        await (provider as any).handleQuickAction('startTrial');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(PROFILE.commands.registerAccess, 'trial');
        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Trial onboarding:');
        expect(finalMessage.content).toContain('Verify the email code');
        expect(finalMessage.content).toContain('Configure your LLM connection');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Register Trial', kind: 'quickAction', quickAction: 'startTrial' }),
            expect.objectContaining({ label: 'Configure LLM', kind: 'quickAction', quickAction: 'setupAI' }),
        ]));
        expect(finalMessage.actions).not.toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Configure Backend', kind: 'quickAction', quickAction: 'configureBackend' }),
        ]));
    });

    it('shows free onboarding guidance when no free licence is cached', async () => {
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
        } as any, {
            getKey: async () => undefined,
            getCachedInfo: () => null,
            validate: async () => { throw new Error('no validation expected'); },
        } as any);

        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue(undefined);

        await (provider as any).handleQuickAction('useFree');

        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(PROFILE.commands.registerAccess, 'free');
        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Free onboarding:');
        expect(finalMessage.content).toContain('Verify the email code');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Use Free', kind: 'quickAction', quickAction: 'useFree' }),
        ]));
        expect(finalMessage.actions).not.toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Configure Backend', kind: 'quickAction', quickAction: 'configureBackend' }),
        ]));
    });

    it('shows guided next steps when a trial licence is active', async () => {
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
        } as any, {
            getKey: async () => 'owlvex_lic_TRIAL_DEV_SEED',
            getCachedInfo: () => ({
                valid: true,
                licenceId: 'lic-trial',
                teamName: 'Trial Team',
                plan: 'trial',
                seats: 1,
                seatsUsed: 0,
                features: {
                    frameworks: ['OWASP'],
                    scansPerMonth: null,
                    promptEditor: true,
                    comparison: true,
                    teamPrompts: false,
                    ciCd: false,
                    pdfReports: false,
                    customRules: false,
                    sso: false,
                    industryPacks: [],
                },
                usage: {
                    scansThisMonth: 2,
                    scansRemaining: null,
                    monthlyLimitReached: false,
                },
                expiresAt: '2026-04-26T00:00:00Z',
            }),
            validate: async () => { throw new Error('no validation expected'); },
        } as any);

        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue(undefined);

        await (provider as any).handleQuickAction('startTrial');

        const finalMessage = (provider as any).messages[(provider as any).messages.length - 1];
        expect(finalMessage.content).toContain('Trial is active for Trial Team.');
        expect(finalMessage.content).toContain('Recommended next steps:');
        expect(finalMessage.actions).toEqual(expect.arrayContaining([
            expect.objectContaining({ label: 'Test Trial Setup', kind: 'quickAction', quickAction: 'testTrialSetup' }),
            expect.objectContaining({ label: 'Configure LLM', kind: 'quickAction', quickAction: 'setupAI' }),
        ]));
    });
