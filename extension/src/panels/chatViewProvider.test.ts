import * as vscode from 'vscode';
import { buildGroundedRemediationHighlights, parseChatIntent } from './chatViewProvider';
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
});
