import * as vscode from 'vscode';
import { buildFindingPromptContext, buildGroundedRemediationHighlights, buildNearbyProjectContext, parseChatIntent } from './chatViewProvider';
import { configureRulePackRuntime, resetRulePackRuntime } from '../frameworks/rulePackRegistry';

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
});
