import * as vscode from 'vscode';
import { generateReportFromSnapshot } from './reportGenerator';
import { ScanResult } from './scanEngine';
import { configureRulePackRuntime, resetRulePackRuntime } from '../frameworks/rulePackRegistry';

describe('reportGenerator', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        resetRulePackRuntime();
    });

    function buildResult(overrides: Partial<ScanResult> = {}): ScanResult {
        return {
            scanId: 'scan-1',
            score: 4.2,
            summary: 'High risk issue found.',
            findings: [
                {
                    id: 'finding-1',
                    line: 3,
                    lineEnd: 4,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'OWASP-A03',
                    title: 'SQL Injection',
                    explanation: 'User input is concatenated into a query.',
                    threat: 'Attackers can read or modify database contents.',
                    fix: 'Use parameterized queries.',
                    confidence: 0.93,
                    canonicalId: 'owlvex.issue.sql_injection.001',
                    canonicalTitle: 'Unsanitized SQL query construction',
                    canonicalFamily: 'family.injection_execution',
                    canonicalFamilyLabel: 'Injection & Execution',
                    stride: ['Tampering', 'Information Disclosure'],
                    matchedSignals: ['CWE:CWE-89', 'sql injection'],
                    mappings: {
                        cwe: ['CWE-89'],
                        owasp: ['A03:2021'],
                        apiOwasp: ['API8:2023'],
                        attack: ['T1190'],
                        capec: ['CAPEC-66'],
                        nist: ['SI-10'],
                    },
                },
            ],
            positives: [],
            metrics: { critical: 0, high: 1, medium: 0, low: 0 },
            durationMs: 120,
            model: 'qwen2.5:7b',
            provider: 'ollama',
            warnings: [],
            packContext: {
                mode: 'fresh',
                packIds: ['owlvex.issue-pack.v1', 'owlvex.issue-mapping-pack.v1'],
                fetchedAt: '2026-04-14T10:00:00.000Z',
            },
            ...overrides,
        };
    }

    it('writes a canonical-first report with code snippets and framework mappings', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(
            Buffer.from([
                'export async function findUser(db, username) {',
                "  const query = `SELECT * FROM users WHERE username = '${username}'`;",
                '  return db.query(query);',
                '}',
            ].join('\n'))
        );
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;

        const snapshot = {
            targetLabel: 'src/probes/example.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\example.js'),
                    result: buildResult(),
                },
            ],
        };

        const reportUri = await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        expect(reportUri.fsPath).toContain('owlvex-scan-report-');
        expect(writeFile).toHaveBeenCalledTimes(1);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('# Owlvex Vulnerability Scan Report');
        expect(written).toContain('- Intelligence source coverage: Fresh Packs: 1');
        expect(written).toContain('## Intelligence Source');
        expect(written).toContain('## Framework Coverage');
        expect(written).toContain('- OWASP: 1 finding(s)');
        expect(written).toContain('## Issue Family Coverage');
        expect(written).toContain('- Injection & Execution: 1 finding(s)');
        expect(written).toContain('## Canonical Findings');
        expect(written).toContain('- Owlvex issue: `owlvex.issue.sql_injection.001`');
        expect(written).toContain('- Issue family: Injection & Execution');
        expect(written).toContain('- Category: unresolved');
        expect(written).toContain('- Intelligence source: Fresh Packs | owlvex.issue-pack.v1, owlvex.issue-mapping-pack.v1 | fetched 2026-04-14T10:00:00.000Z');
        expect(written).toContain('- Matched signals: CWE:CWE-89, sql injection');
        expect(written).toContain('- Recommended fix: Use parameterized queries or prepared statements and validate input at trust boundaries.');
        expect(written).toContain('- Remediation sources: OWASP SQL Injection Prevention Cheat Sheet');
        expect(written).toContain('- Model implementation note: Use parameterized queries.');
        expect(written).toContain('## Detailed Findings by Owlvex Issue');
        expect(written).toContain('- Issue family: Injection & Execution');
        expect(written).toContain('#### File-level evidence');
        expect(written).toContain('- `example.js` at L3-4');
        expect(written).toContain('  Original framework match: OWASP');
        expect(written).toContain('  Recommended remediation: Use parameterized queries or prepared statements and validate input at trust boundaries.');
        expect(written).toContain('## Framework Correlation View');
        expect(written).toContain('- `owlvex.issue.sql_injection.001` in `example.js` at L3');
        expect(written).toContain('  Code involved in the reasoning:');
        expect(written).toContain("SELECT * FROM users WHERE username = '${username}'");
    });

    it('handles snapshots with no findings and includes scan errors', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        const snapshot = {
            targetLabel: 'src/probes/clean.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: ['clean.js: model timeout'],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\clean.js'),
                    result: buildResult({
                        score: 9.5,
                        summary: 'No meaningful issues found.',
                        findings: [],
                        metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- No framework-mapped findings were returned.');
        expect(written).toContain('No findings were returned.');
        expect(written).toContain('## Scan Errors');
        expect(written).toContain('- clean.js: model timeout');
    });

    it('includes scan warnings when a scan completed with recorder issues', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        const snapshot = {
            targetLabel: 'src/probes/warn.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\warn.js'),
                    result: buildResult({
                        warnings: ['Failed to record scan: Internal Server Error'],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Scan warnings: 1');
        expect(written).toContain('## Scan Warnings');
        expect(written).toContain('- warn.js: Failed to record scan: Internal Server Error');
    });

    it('normalizes string-based stride and matched signals without crashing', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('console.log("ok");'));
        const snapshot = {
            targetLabel: 'src/probes/stringy.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\stringy.js'),
                    result: buildResult({
                        findings: [
                            {
                                ...buildResult().findings[0],
                                stride: 'Tampering, Information Disclosure' as any,
                                matchedSignals: 'CWE:CWE-89, sql injection' as any,
                            },
                        ],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- STRIDE: Tampering, Information Disclosure');
        expect(written).toContain('- Matched signals: CWE:CWE-89, sql injection');
    });

    it('prefers remediation-pack guidance with framework actions, validation, and unsafe alternatives', async () => {
        configureRulePackRuntime(
            undefined,
            undefined,
            {
                entries: [{
                    id: 'owlvex.remediation.sql_injection.001',
                    issue_id: 'owlvex.issue.sql_injection.001',
                    title: 'Canonical remediation for SQL injection',
                    canonical_fix_summary: 'Use parameter binding and allow-list dynamic SQL structure.',
                    framework_variants: [{
                        framework: 'Express',
                        summary: 'Use placeholders and values arrays in your database client.',
                        recommended_actions: [
                            'Replace string-built SQL with placeholders.',
                            'Allow-list dynamic sort fields.',
                        ],
                    }],
                    validation_steps: ['Replay the injection payload and confirm it is treated as data.'],
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

        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('app.get("/users");'));
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        const snapshot = {
            targetLabel: 'src/probes/express.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\express.js'),
                    result: buildResult({
                        findings: [
                            {
                                ...buildResult().findings[0],
                                framework: 'Express',
                                fix: 'Parameterize the query.',
                            },
                        ],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Framework-specific guidance (Express): Use placeholders and values arrays in your database client.');
        expect(written).toContain('- Recommended actions: Replace string-built SQL with placeholders. | Allow-list dynamic sort fields.');
        expect(written).toContain('- Validation steps: Replay the injection payload and confirm it is treated as data.');
        expect(written).toContain('- Unsafe alternatives to avoid: Manual quote escaping.');
        expect(written).toContain('  Framework-specific guidance (Express): Use placeholders and values arrays in your database client.');
    });
});
