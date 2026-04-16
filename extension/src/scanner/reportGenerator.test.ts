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
            score: 7,
            summary: 'High risk issue found.',
            frameworks: ['OWASP', 'STRIDE', 'CWE', 'MITRE', 'NIST'],
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
                    provenance: 'ai',
                    scanTier: 'TARGETED_AI',
                    confidenceTier: 'PLAUSIBLE',
                    corroboration: 'CORROBORATED',
                    canonicalId: 'owlvex.issue.sql_injection.001',
                    canonicalTitle: 'Unsanitized SQL query construction',
                    canonicalFamily: 'family.injection_execution',
                    canonicalFamilyLabel: 'Injection & Execution',
                    stride: ['Tampering', 'Information Disclosure'],
                    matchedSignals: ['CWE:CWE-89', 'sql injection'],
                    likelihood: 'MEDIUM',
                    likelihoodReasons: ['Dynamic SQL uses user-controlled input directly.'],
                    riskScore: 7,
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
            projectContextSummary: 'inline project contract',
            packContext: {
                mode: 'fresh',
                packIds: ['owlvex.issue-pack.v1', 'owlvex.issue-mapping-pack.v1'],
                fetchedAt: '2026-04-14T10:00:00.000Z',
            },
            ...overrides,
        };
    }

    it('writes a compact report with per-file findings and code snippets', async () => {
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
        expect(written).toContain('- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5');
        expect(written).toContain('- Intelligence source coverage: Fresh Packs: 1');
        expect(written).toContain('- Coverage posture: Full scan posture for current provider/runtime state');
        expect(written).toContain('- Scan tier posture: targeted_ai: 1');
        expect(written).toContain('- Corroboration posture: corroborated: 1');
        expect(written).toContain('- Project context: inline project contract');
        expect(written).toContain('- Average file risk score: 7.0/10');
        expect(written).toContain('- Score guide: file risk score equals the highest remaining finding risk in that file; finding risk is the 0-10 risk of a specific issue.');
        expect(written).toContain('## Findings By File');
        expect(written).toContain('### example.js');
        expect(written).toContain('- File risk score: 7.0/10');
        expect(written).toContain('- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5');
        expect(written).toContain('- Intelligence source: Fresh Packs | owlvex.issue-pack.v1, owlvex.issue-mapping-pack.v1 | fetched 2026-04-14T10:00:00.000Z');
        expect(written).toContain('- Coverage posture: Normal coverage for this file');
        expect(written).toContain('- Scan tier posture: targeted_ai: 1');
        expect(written).toContain('- Corroboration posture: corroborated: 1');
        expect(written).toContain('- Project context: inline project contract');
        expect(written).toContain('- Score guide: fix the highest finding risk first; the file risk score then drops to the next-highest remaining finding, and reaches 0 when no findings remain.');
        expect(written).toContain('| Unsanitized SQL query construction | mode targeted_ai \\| tier plausible \\| corroboration corroborated \\| impact high \\| likelihood medium \\| risk 7/10 | AI 93% |');
        expect(written).toContain('- Location: `example.js` at L3-4');
        expect(written).toContain('- Finding risk: HIGH impact / MEDIUM likelihood / 7/10');
        expect(written).toContain('- Scan tier: TARGETED_AI');
        expect(written).toContain('- Confidence tier: PLAUSIBLE');
        expect(written).toContain('- Corroboration: CORROBORATED');
        expect(written).toContain('- Why it matters: User input is concatenated into a query.');
        expect(written).toContain('- What to change: Separate query structure from untrusted data with parameter binding or ORM-safe APIs');
        expect(written).toContain('- Safe pattern: Use parameterized queries.');
        expect(written).toContain('- Why likely: Dynamic SQL uses user-controlled input directly.');
        expect(written).toContain('- Matched signals: CWE:CWE-89, sql injection');
        expect(written).toContain('- Sources: OWASP SQL Injection Prevention Cheat Sheet');
        expect(written).toContain('- AI grounding: Curated framework pack | OWASP SQL Injection Prevention Cheat Sheet');
        expect(written).toContain('- Code involved in the reasoning:');
        expect(written).toContain("SELECT * FROM users WHERE username = '${username}'");
        expect(written).not.toContain('## Intelligence Source');
        expect(written).not.toContain('## Framework Coverage');
        expect(written).not.toContain('## Canonical Findings');
        expect(written).not.toContain('## Framework Correlation View');
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
                        score: 0,
                        summary: 'No meaningful issues found.',
                        findings: [],
                        metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Corroboration posture: No findings to corroborate');
        expect(written).toContain('## Findings By File');
        expect(written).toContain('No detailed findings were returned.');
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

    it('uses warning-aware summaries for clean files instead of degraded raw scan prose', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        const snapshot = {
            targetLabel: 'src/probes/degraded-clean.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\degraded-clean.js'),
                    result: buildResult({
                        score: 10,
                        summary: 'No deterministic findings. Backend or AI services were unavailable, so Owlvex returned local-only results.',
                        findings: [],
                        metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                        warnings: ['AI provider unavailable: Azure Foundry error: 429'],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Scan warnings: 1');
        expect(written).toContain('- Coverage posture: Partial AI coverage in this scan');
        expect(written).toContain('- Corroboration posture: No findings to corroborate');
        expect(written).toContain('No detailed findings were returned.');
        expect(written).toContain('## Scan Warnings');
        expect(written).not.toContain('No deterministic findings. Backend or AI services were unavailable, so Owlvex returned local-only results.');
    });

    it('summarizes mixed corroboration posture across a scan and per file', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const snapshot = {
            targetLabel: 'src/probes/mixed.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\mixed.js'),
                    result: buildResult({
                        findings: [
                            {
                                ...buildResult().findings[0],
                                provenance: 'deterministic',
                                scanTier: 'STATIC',
                                confidenceTier: 'PROVEN',
                                corroboration: 'PROVEN',
                                ruleCode: 'SM-002',
                            },
                            {
                                ...buildResult().findings[0],
                                id: 'finding-2',
                                line: 8,
                                lineEnd: 8,
                                title: 'Potential CSRF issue',
                                canonicalTitle: 'Missing CSRF protection on state-changing request',
                                corroboration: 'PARTIAL',
                            },
                            {
                                ...buildResult().findings[0],
                                id: 'finding-3',
                                line: 12,
                                lineEnd: 12,
                                title: 'Potential open redirect',
                                canonicalTitle: 'Open redirect using untrusted destination',
                                corroboration: 'UNVERIFIED',
                            },
                        ],
                        metrics: { critical: 0, high: 3, medium: 0, low: 0 },
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Scan tier posture: static: 1 | targeted_ai: 2');
        expect(written).toContain('- Corroboration posture: proven: 1 | partial: 1 | unverified: 1');
        expect(written).toContain('### mixed.js');
        expect(written).toContain('- Scan tier posture: static: 1 | targeted_ai: 2');
        expect(written).toContain('- Corroboration posture: proven: 1 | partial: 1 | unverified: 1');
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
        expect(written).toContain('- Safe pattern: Use placeholders and values arrays in your database client.');
        expect(written).toContain('- Suggested steps: Replace string-built SQL with placeholders. | Allow-list dynamic sort fields.');
        expect(written).toContain('- Validate with: Replay the injection payload and confirm it is treated as data.');
        expect(written).toContain('- Avoid: Manual quote escaping.');
        expect(written).toContain('## Findings By File');
    });

    it('filters mappings and STRIDE to the frameworks selected for the scan', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const snapshot = {
            targetLabel: 'src/probes/clean-code-only.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\clean-code-only.js'),
                    result: buildResult({
                        frameworks: ['CLEANCODE'],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).not.toContain('- Mappings:');
        expect(written).not.toContain('- STRIDE:');
        expect(written).toContain('- Frameworks in scope: CLEANCODE 2024-curated');
        expect(written).toContain('- Sources: OWASP SQL Injection Prevention Cheat Sheet');
    });

    it('keeps a stable report headline posture for repo-ai findings', async () => {
        jest.useFakeTimers().setSystemTime(new Date('2026-04-16T00:00:00.000Z'));
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const snapshot = {
            targetLabel: 'tools/demo-app',
            outputRoot: vscode.Uri.file('d:\\repo\\tools\\demo-app'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\tools\\demo-app\\src\\tokens.js'),
                    result: buildResult({
                        score: 9,
                        findings: [
                            {
                                ...buildResult().findings[0],
                                scanTier: 'REPO_AI',
                                corroboration: 'CORROBORATED',
                                riskScore: 9,
                            },
                        ],
                        provider: 'azure-foundry',
                        model: 'owlvex-gpt54mini',
                        summary: 'Repo context strengthened one finding.',
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        const summarySlice = written
            .split('## Findings By File')[0]
            .trim();

        expect(summarySlice).toMatchInlineSnapshot(`
"# Owlvex Vulnerability Scan Report

Generated: 2026-04-16T00:00:00.000Z
Target: \`tools/demo-app\`
Report location: \`d:\\repo\\tools\\demo-app\`

## Summary

- Files scanned: 1
- Files with findings: 1
- Total findings: 1
- Average file risk score: 9.0/10
- Deterministic findings: 0
- Intelligence source coverage: Fresh Packs: 1
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5
- Errors: 0
- Scan warnings: 0
- Coverage posture: Full scan posture for current provider/runtime state
- Primary scan mode: REPO_AI
- Scan tier posture: repo_ai: 1
- Corroboration posture: corroborated: 1
- Project context: inline project contract
- Score guide: file risk score equals the highest remaining finding risk in that file; finding risk is the 0-10 risk of a specific issue."
`);
        jest.useRealTimers();
    });

});
