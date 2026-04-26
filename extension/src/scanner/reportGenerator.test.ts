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
                    aiReviewScores: {
                        finder: 0.88,
                        verifier: 0.91,
                        skeptic: 0.9,
                        final: 0.93,
                    },
                    aiReviewNotes: {
                        finder: 'User input is concatenated into a query.',
                        verifier: 'The code builds SQL text directly from user-controlled input.',
                        skeptic: 'No parameter binding or escaping guard is visible around the query construction.',
                    },
                    canonicalId: 'owlvex.issue.sql_injection.001',
                    canonicalTitle: 'Unsanitized SQL query construction',
                    canonicalFamily: 'family.injection_execution',
                    canonicalFamilyLabel: 'Injection & Execution',
                    stride: ['Tampering', 'Information Disclosure'],
                    matchedSignals: ['CWE:CWE-89', 'sql injection'],
                    likelihood: 'MEDIUM',
                    likelihoodReasons: ['Dynamic SQL uses user-controlled input directly.'],
                    riskScore: 7,
                    evidenceContract: {
                        issueType: 'sql-injection',
                        verdict: 'confirmed',
                        source: {
                            kind: 'source',
                            label: 'User-controlled username',
                            expression: 'username',
                            line: 2,
                        },
                        flow: [{
                            kind: 'assignment',
                            label: 'SQL string built from username',
                            expression: "const query = `SELECT * FROM users WHERE username = '${username}'`",
                            line: 2,
                        }],
                        sink: {
                            kind: 'sink',
                            label: 'SQL execution',
                            expression: 'db.query(query)',
                            line: 3,
                        },
                        guard: {
                            status: 'missing',
                            label: 'Parameter binding',
                            reason: 'No parameter binding is visible.',
                        },
                        rationale: 'User-controlled input reaches a SQL execution sink through string construction.',
                        proofStatus: 'ai_plausible',
                        attackerAction: 'Send a crafted username that changes SQL semantics.',
                        requiredGuard: ['Parameterized query'],
                        counterEvidence: ['No placeholder binding found'],
                        responsibilityLayer: 'route-policy',
                        proofChecks: [{
                            check: 'source reaches sink',
                            status: 'pass',
                            evidence: 'query is passed to db.query',
                        }],
                    },
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
            aiUsage: { requestCount: 3, totalTokens: 62 },
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
        expect(written).toContain('- Start with: Unsanitized SQL query construction in `example.js` (7/10 risk).');
        expect(written).toContain('- This scan established: 1 reviewed with targeted AI.');
        expect(written).toContain('- Highest file risk: 7.0/10');
        expect(written).toContain('- Clean files: 0/1');
        expect(written).toContain('- Confidence posture: 1 cross-checked');
        expect(written).not.toContain('- Average file risk score:');
        expect(written).toContain('- AI findings needing manual review: 0');
        expect(written).toContain('## AI Usage');
        expect(written).toContain('- Provider/model mix: ollama / qwen2.5:7b');
        expect(written).toContain('- AI requests: 3');
        expect(written).toContain('- Total AI tokens: 62');
        expect(written).toContain('- Estimated cost: not yet available');
        expect(written).not.toContain('Provider rate limit note:');
        expect(written).toContain('- Coverage: Normal for the current provider and runtime state');
        expect(written).toContain('- Knowledge sources: Fresh packs (1)');
        expect(written).toContain('- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5');
        expect(written).toContain('- Project context: inline project contract');
        expect(written).toContain('## Fix First');
        expect(written).toContain('- `example.js` (7.0/10): Unsanitized SQL query construction.');
        expect(written).toContain('## How To Read This Report');
        expect(written).toContain('| Report field | What it means | How to use it |');
        expect(written).toContain('| Confidence | Evidence posture for the finding, not an exact probability | Use this as a triage signal, not a mathematical certainty |');
        expect(written).toContain('## Findings By File');
        expect(written).toContain('### example.js');
        expect(written).toContain('- File risk score: 7.0/10');
        expect(written).toContain('- AI usage: 3 request(s), 62 token(s)');
        expect(written).toContain('- Fix first: Unsanitized SQL query construction (7/10 risk)');
        expect(written).toContain('- Why this matters: User input is concatenated into a query.');
        expect(written).toContain('- What to change: Keep untrusted values out of SQL text with parameter binding or ORM-safe APIs');
        expect(written).toContain('- Confidence: 1 cross-checked');
        expect(written).toContain('- Manual review: 0 AI finding(s) needing review');
        expect(written).toContain('- Knowledge sources: Fresh Packs | owlvex.issue-pack.v1, owlvex.issue-mapping-pack.v1 | fetched 2026-04-14T10:00:00.000Z');
        expect(written).toContain('- Coverage: Normal for this file');
        expect(written).toContain('#### Technical Details');
        expect(written).toContain('- Analysis mode: Targeted AI review');
        expect(written).toContain('- Analysis mix: targeted_ai: 1');
        expect(written).toContain('- Evidence: corroborated: 1');
        expect(written).toContain('- Project context: inline project contract');
        expect(written).toContain('| Unsanitized SQL query construction | mode Targeted AI review \\| confidence AI-reviewed \\| evidence Validated by AI review \\| AI signal High (93% final) \\| review path finder+verifier+skeptic \\| impact high \\| likelihood medium \\| risk 7/10 | High AI signal, final 93% (finder+verifier+skeptic; Validated by AI review) |');
        expect(written).toContain('- Location: `example.js` at L3-4');
        expect(written).toContain('- Finding risk: HIGH impact / MEDIUM likelihood / 7/10');
        expect(written).toContain('- Analysis mode: Targeted AI review');
        expect(written).toContain('- Confidence: AI-reviewed');
        expect(written).toContain('- AI signal: High, final 93%');
        expect(written).toContain('- AI review path: finder+verifier+skeptic');
        expect(written).toContain('- AI review trace: finder High | verifier High | skeptic High | final High (raw audit: finder 88%, verifier 91%, skeptic 90%, final 93%)');
        expect(written).toContain('- Evidence: Validated by AI review');
        expect(written).toContain('- Finder said: User input is concatenated into a query.');
        expect(written).toContain('- Verifier said: The code builds SQL text directly from user-controlled input.');
        expect(written).toContain('- Skeptic said: No parameter binding or escaping guard is visible around the query construction.');
        expect(written).toContain('- Why it matters: User input is concatenated into a query.');
        expect(written).toContain('- What to change: Keep untrusted values out of SQL text with parameter binding or ORM-safe APIs');
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

    it('writes a summary report focused on developer action', async () => {
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

        const reportUri = await generateReportFromSnapshot(snapshot.outputRoot, snapshot, { variant: 'summary' });

        expect(reportUri.fsPath).toContain('owlvex-summary-report-');
        expect(writeFile).toHaveBeenCalledTimes(1);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('# Owlvex Summary Report');
        expect(written).toContain('This is the developer summary view.');
        expect(written).toContain('## What To Fix First');
        expect(written).toContain('## Confirmed Or AI-Reviewed Findings');
        expect(written).toContain('### Unsanitized SQL query construction');
        expect(written).toContain('- Status: AI-reviewed');
        expect(written).toContain('- What to change: Keep untrusted values out of SQL text with parameter binding or ORM-safe APIs');
        expect(written).toContain('- Code involved:');
        expect(written).not.toContain('## AI Usage');
        expect(written).not.toContain('## Findings By File');
    });

    it('renders evidence contracts for deterministic findings', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(
            Buffer.from([
                'function downloadFile(req, res) {',
                "  const fullPath = path.join('/var/app/uploads', req.query.file);",
                '  res.sendFile(fullPath);',
                '}',
            ].join('\n'))
        );

        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        const result = buildResult({
            score: 9,
            model: 'static',
            provider: 'local',
            aiUsage: { requestCount: 0, totalTokens: 0 },
            findings: [
                {
                    id: 'finding-pt-1',
                    line: 3,
                    lineEnd: 3,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'PT-001',
                    title: 'Path Traversal',
                    explanation: 'A request-derived filesystem path reaches a file-serving sink.',
                    threat: 'Attackers may read files outside the allowed export directory.',
                    fix: 'Resolve paths against a fixed base directory and reject escapes.',
                    confidence: 1,
                    provenance: 'deterministic',
                    scanTier: 'STATIC',
                    confidenceTier: 'PROVEN',
                    corroboration: 'PROVEN',
                    canonicalId: 'owlvex.issue.path_traversal.001',
                    canonicalTitle: 'Path Traversal',
                    canonicalFamily: 'family.access_control_authorization',
                    canonicalFamilyLabel: 'Access Control & Authorization',
                    likelihood: 'HIGH',
                    likelihoodReasons: ['A request-derived file path reaches a filesystem sink without a visible boundary check.'],
                    riskScore: 9,
                    evidenceContract: {
                        issueType: 'path-traversal',
                        verdict: 'confirmed',
                        source: {
                            kind: 'source',
                            label: 'Request-controlled path segment',
                            expression: 'req.query.file',
                            line: 2,
                        },
                        flow: [
                            {
                                kind: 'path-construction',
                                label: 'Path constructed in fullPath',
                                expression: "const fullPath = path.join('/var/app/uploads', req.query.file)",
                                line: 2,
                            },
                        ],
                        sink: {
                            kind: 'sink',
                            label: 'Filesystem read or file-serving sink',
                            expression: 'res.sendFile(fullPath)',
                            line: 3,
                        },
                        guard: {
                            status: 'missing',
                            label: 'Base-directory containment guard',
                            reason: 'No recognized allowlist or containment check is visible.',
                        },
                        rationale: 'Request-controlled input contributes to a constructed filesystem path that reaches a filesystem sink without a recognized containment guard.',
                    },
                },
            ],
            metrics: { critical: 0, high: 1, medium: 0, low: 0 },
        });

        await generateReportFromSnapshot(vscode.Uri.file('d:\\repo\\src'), {
            targetLabel: 'src/download.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\download.js'),
                    result,
                },
            ],
        });

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Engine evidence: Structured contracts: 1/1 | confirmed: 1 | missing guards: 1 | deterministic gaps: 0 | AI without contract: 0');
        expect(written).toContain('- Evidence contract: confirmed path-traversal');
        expect(written).toContain('- Source: Request-controlled path segment (L2: `req.query.file`)');
        expect(written).toContain("- Flow: Path constructed in fullPath (L2: `const fullPath = path.join('/var/app/uploads', req.query.file)`)");
        expect(written).toContain('- Sink: Filesystem read or file-serving sink (L3: `res.sendFile(fullPath)`)');
        expect(written).toContain('- Guard: missing Base-directory containment guard. No recognized allowlist or containment check is visible.');
        expect(written).toContain('- Rationale: Request-controlled input contributes to a constructed filesystem path');
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
        expect(written).toContain('- Confidence posture: No findings to validate.');
        expect(written).toContain('- Engine evidence: No findings to prove.');
        expect(written).toContain('- Start with: no active findings were identified in this scan.');
        expect(written).toContain('- Highest file risk: 0.0/10');
        expect(written).toContain('- Clean files: 1/1');
        expect(written).toContain('- AI findings needing manual review: 0');
        expect(written).toContain('## Fix First');
        expect(written).toContain('No immediate action needed from this scan.');
        expect(written).toContain('## Findings By File');
        expect(written).toContain('### clean.js');
        expect(written).toContain('- File risk score: 0.0/10');
        expect(written).toContain('- Findings: 0');
        expect(written).toContain('- Summary: No findings detected.');
        expect(written).toContain('## Scan Errors');
        expect(written).toContain('- clean.js: model timeout');
    });

    it('renders provider comparison notes in full reports', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;

        await generateReportFromSnapshot(vscode.Uri.file('d:\\repo\\src'), {
            targetLabel: 'src/example.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\example.js'),
                    result: buildResult({
                        providerComparisonNotes: [
                            'Provider disagreement: gpt / model-a previously reported 0 findings for example.js; anthropic / model-b now reports 1. Treat clean scans as provider/model-scoped evidence.',
                        ],
                        providerDisagreementProofs: [
                            {
                                verdict: 'PROVEN_BY_SINK',
                                reason: 'Deterministic evidence confirms source-to-sink flow with no recognized guard.',
                                issueType: 'client-controlled-query-filter',
                                source: 'req.body.filter',
                                sink: 'matchesFilter(user, filter)',
                                guard: 'Server-side field/operator allowlist',
                            },
                        ],
                    }),
                },
            ],
        });

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('## Provider Comparison Notes');
        expect(written).toContain('- Provider disagreement: gpt / model-a previously reported 0 findings for example.js; anthropic / model-b now reports 1. Treat clean scans as provider/model-scoped evidence.');
        expect(written).toContain('- Proof pass: example.js: PROVEN_BY_SINK - Deterministic evidence confirms source-to-sink flow with no recognized guard. | issue client-controlled-query-filter | source `req.body.filter` | sink `matchesFilter(user, filter)` | guard Server-side field/operator allowlist');
        expect(written).toContain('- Provider comparison: Provider disagreement: gpt / model-a previously reported 0 findings for example.js; anthropic / model-b now reports 1. Treat clean scans as provider/model-scoped evidence.');
        expect(written).toContain('- Provider disagreement proof: PROVEN_BY_SINK: Deterministic evidence confirms source-to-sink flow with no recognized guard.');
    });

    it('renders provider comparison notes in summary reports', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;

        await generateReportFromSnapshot(vscode.Uri.file('d:\\repo\\src'), {
            targetLabel: 'src/example.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\example.js'),
                    result: buildResult({
                        providerComparisonNotes: [
                            'Provider-scoped clean result: anthropic / model-b reports 0 findings for example.js, while gpt / model-a previously reported 2. Consider a second-provider review before calling the file clean.',
                        ],
                        providerDisagreementProofs: [
                            {
                                verdict: 'UNRESOLVED',
                                reason: 'Provider disagreement exists, and this scan has no findings to prove or disprove.',
                            },
                        ],
                    }),
                },
            ],
        }, { variant: 'summary' });

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('## Provider Comparison Notes');
        expect(written).toContain('- Provider-scoped clean result: anthropic / model-b reports 0 findings for example.js, while gpt / model-a previously reported 2. Consider a second-provider review before calling the file clean.');
        expect(written).toContain('- Proof pass: example.js: UNRESOLVED - Provider disagreement exists, and this scan has no findings to prove or disprove.');
    });

    it('marks unverified high-confidence AI findings as needing manual review', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        const snapshot = {
            targetLabel: 'src/probes/ssrf.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\ssrf.js'),
                    result: buildResult({
                        findings: [
                            {
                                ...buildResult().findings[0],
                                id: 'finding-ssrf',
                                title: 'Server-side request forgery',
                                explanation: 'User supplied URL reaches fetch without validation.',
                                fix: 'Validate outbound URLs against an allow-list.',
                                confidence: 0.95,
                                resolverConfidence: 0.95,
                                corroboration: 'UNVERIFIED',
                                aiReviewScores: { finder: 0.95, final: 0.95 },
                                aiReviewNotes: { finder: 'User supplied URL reaches fetch without validation.' },
                                canonicalId: 'owlvex.issue.ssrf.001',
                                canonicalTitle: 'Server-side request forgery (SSRF) through untrusted destination',
                                riskScore: 9,
                            },
                        ],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- AI findings needing manual review: 1');
        expect(written).toContain('- Confidence posture: 1 need manual review');
        expect(written).toContain('Manual review recommended before acting.');
        expect(written).toContain('- Manual review: 1 AI finding(s) needing review');
        expect(written).toContain('- AI signal: High, final 95% (manual review recommended)');
        expect(written).toContain('- AI review path: finder');
        expect(written).toContain('- Evidence: Finder-only AI review');
        expect(written).toContain('- Review note: This AI finding is not fully corroborated or has low confidence.');
    });

    it('does not call finder-only AI confidence independently validated', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('async function approveRefund(req, res, refunds) {}'));
        const snapshot = {
            targetLabel: 'src/probes/approval.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\approval.js'),
                    result: buildResult({
                        findings: [
                            {
                                ...buildResult().findings[0],
                                title: 'Broken function-level authorization',
                                canonicalTitle: 'Broken function-level authorization',
                                confidence: 0.96,
                                resolverConfidence: 0.96,
                                corroboration: 'CORROBORATED',
                                scanTier: 'REPO_AI',
                                aiReviewScores: { finder: 0.96, final: 0.96 },
                                aiReviewNotes: {
                                    finder: 'Only authentication is checked before a privileged approval action.',
                                },
                                riskScore: 9,
                            },
                        ],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('| Broken function-level authorization | mode Repo-context AI review \\| confidence AI-reviewed \\| evidence Finder high confidence, not independently verified \\| AI signal High (96% final) \\| review path finder \\| impact high \\| likelihood medium \\| risk 9/10 | High AI signal, final 96% (finder; Finder high confidence, not independently verified) |');
        expect(written).toContain('- AI signal: High, final 96%');
        expect(written).toContain('- AI review path: finder');
        expect(written).toContain('- AI review trace: finder High | verifier Unknown | skeptic Unknown | final High (raw audit: finder 96%, verifier n/a, skeptic n/a, final 96%)');
        expect(written).toContain('- Evidence: Finder high confidence, not independently verified');
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

    it('renders engine telemetry when sink-first evidence is available', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(
            Buffer.from([
                'app.get("/user", async (req, res) => {',
                '  return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);',
                '});',
            ].join('\n')),
        );

        await generateReportFromSnapshot(vscode.Uri.file('d:\\repo\\src'), {
            targetLabel: 'src',
            outputRoot: vscode.Uri.file('d:\\repo\\src'),
            errors: [],
            results: [{
                uri: vscode.Uri.file('d:\\repo\\src\\users.js'),
                result: buildResult({
                    engineTelemetry: {
                        sinkInventory: {
                            total: 2,
                            byFamily: {
                                'sql-injection': 1,
                                ssrf: 1,
                            },
                            guarded: 1,
                            missingGuard: 1,
                            unknownGuard: 0,
                        },
                        aiFindings: {
                            proposed: 3,
                            afterStaticFilter: 2,
                            afterCorroboration: 1,
                            finalSurvivors: 1,
                        },
                        safeProbes: {
                            run: 2,
                            confirmed: 1,
                            counterEvidence: 1,
                            unsupported: 0,
                            inconclusive: 0,
                            promoted: 1,
                            downgraded: 0,
                            dropped: 1,
                            manualReview: 0,
                        },
                    },
                }),
            }],
        });

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Local sinks discovered before AI: 2 (sql-injection: 1 | ssrf: 1)');
        expect(written).toContain('- Sink guard posture: guarded 1 | missing guard 1 | unknown 0');
        expect(written).toContain('- AI finding funnel: proposed 3 | after static/sink/probe filter 2 | after corroboration 1 | final AI survivors 1');
        expect(written).toContain('- Safe probes: run 2 | confirmed 1 | counter-evidence 1 | unsupported 0 | inconclusive 0');
        expect(written).toContain('- Probe decisions: promoted 1 | downgraded 0 | dropped 1 | manual review 0');
        expect(written).toContain('- Probe quality signal: resolved 2/2 (100%) | confirmed paths 1 | AI candidates removed or downgraded 1 | manual review residue 0');
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
        expect(written).toContain('- Coverage: Partial AI coverage in this scan');
        expect(written).toContain('- Provider rate limit note: this scan saw a 429/rate-limit signal. If it repeats, configure `owlvex.providerThrottleOverrides` for the affected provider.');
        expect(written).toContain('- AI findings needing manual review: 0');
        expect(written).toContain('- This scan did not produce active findings. Coverage and provider status are listed below.');
        expect(written).toContain('### degraded-clean.js');
        expect(written).toContain('- Summary: No findings detected. Scan completed with provider/backend warnings.');
        expect(written).toContain('- Coverage: Partial AI coverage or deterministic-only fallback affected this file');
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
        expect(written).toContain('- Analysis mix: static: 1 | targeted_ai: 2');
        expect(written).toContain('- Evidence: proven: 1 | partial: 1 | unverified: 1');
        expect(written).toContain('### mixed.js');
        expect(written).toContain('- Confidence: 1 verified | 1 partially validated | 2 need manual review');
    });

    it('states when AI review was not used for the final finding set in a static-proof file', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const snapshot = {
            targetLabel: 'src/probes/static-only.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\static-only.js'),
                    result: buildResult({
                        findings: [
                            {
                                ...buildResult().findings[0],
                                provenance: 'deterministic',
                                scanTier: 'STATIC',
                                confidenceTier: 'PROVEN',
                                corroboration: 'PROVEN',
                                ruleCode: 'AC-001',
                                title: 'Missing object-level authorization',
                                canonicalTitle: 'Missing object-level authorization',
                                canonicalId: 'owlvex.issue.idor.001',
                                aiReviewScores: undefined,
                                aiReviewNotes: undefined,
                            },
                        ],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Analysis mode: Static proof');
        expect(written).toContain('- AI review: not used for the final finding set in this file');
        expect(written).not.toContain('- AI pass scores:');
    });

    it('keeps helper-layer extras out of Fix First', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('function audit() {}'));
        const finding = {
            ...buildResult().findings[0],
            id: 'helper-extra-1',
            title: 'Missing audit trail for authorization decision',
            canonicalTitle: 'Missing audit trail for authorization decision',
            evidenceContract: undefined,
            provenance: 'ai' as const,
            confidenceTier: 'PLAUSIBLE' as const,
            corroboration: 'CORROBORATED' as const,
        };

        await generateReportFromSnapshot(vscode.Uri.file('d:\\repo\\src'), {
            targetLabel: 'src/middleware/auth.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src'),
            errors: [],
            results: [{
                uri: vscode.Uri.file('d:\\repo\\src\\middleware\\auth.js'),
                result: buildResult({
                    findings: [finding],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
            }],
        });

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Start with: no proof-promoted findings; review Possible Extra Findings before acting.');
        expect(written).toContain('## Possible Extra Findings');
        expect(written).toContain('- `middleware/auth.js`: Missing audit trail for authorization decision (helper-layer extra).');
        expect(written).toContain('- Fix first: no proof-promoted finding in this file');
        expect(written).not.toContain('- `middleware/auth.js` (7.0/10): Missing audit trail for authorization decision.');
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
        expect(written).toContain('- Canonical grounding: OWASP SQL Injection Prevention Cheat Sheet');
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

    it('flags low-confidence AI findings for manual review', async () => {
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const snapshot = {
            targetLabel: 'src/probes/low-confidence.js',
            outputRoot: vscode.Uri.file('d:\\repo\\src\\probes'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\src\\probes\\low-confidence.js'),
                    result: buildResult({
                        findings: [
                            {
                                ...buildResult().findings[0],
                                confidence: 0.65,
                                resolverConfidence: 0.65,
                                aiReviewScores: {
                                    finder: 0.62,
                                    verifier: 0.68,
                                    skeptic: 0.64,
                                    final: 0.65,
                                },
                            },
                        ],
                    }),
                },
            ],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- AI findings needing manual review: 1');
        expect(written).toContain('- Manual review: 1 AI finding(s) needing review');
        expect(written).toContain('| Unsanitized SQL query construction | mode Targeted AI review \\| confidence AI-reviewed \\| evidence Validated by AI review \\| AI signal Low (65% final) \\| review path finder+verifier+skeptic \\| impact high \\| likelihood medium \\| risk 7/10 \\| manual review recommended | Low AI signal, final 65% (finder+verifier+skeptic; Validated by AI review; manual review recommended) |');
        expect(written).toContain('- AI signal: Low, final 65% (manual review recommended)');
        expect(written).toContain('- AI review path: finder+verifier+skeptic');
        expect(written).toContain('- AI review trace: finder Low | verifier Low | skeptic Low | final Low (raw audit: finder 62%, verifier 68%, skeptic 64%, final 65%)');
        expect(written).toContain('- Review note: This AI finding is not fully corroborated or has low confidence. Verify the classification, title, and remediation against the code before acting on it.');
    });

    it('keeps a stable report headline posture for repo-ai findings', async () => {
        jest.useFakeTimers().setSystemTime(new Date('2026-04-16T00:00:00.000Z'));
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const x = 1;'));
        const snapshot = {
            targetLabel: 'tools/benchmark-app',
            outputRoot: vscode.Uri.file('d:\\repo\\tools\\benchmark-app'),
            errors: [],
            results: [
                {
                    uri: vscode.Uri.file('d:\\repo\\tools\\benchmark-app\\src\\tokens.js'),
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
                        model: 'test-foundry-deployment-secondary',
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
Target: \`tools/benchmark-app\`
Report location: \`d:\\repo\\tools\\benchmark-app\`

## Summary

- Start with: Unsanitized SQL query construction in \`src/tokens.js\` (9/10 risk).
- This scan established: 1 strengthened with repo context.
- Highest file risk: 9.0/10
- Clean files: 0/1
- Confidence posture: 1 cross-checked
- Engine evidence: Structured contracts: 1/1 | confirmed: 1 | missing guards: 1 | deterministic gaps: 0 | AI without contract: 0
- Proof posture: static proven: 0 | AI plausible: 1 | counter-evidence: 0 | unproven extras: 0

## Fix First

- \`src/tokens.js\` (9.0/10): Unsanitized SQL query construction. Keep untrusted values out of SQL text with parameter binding or ORM-safe APIs, constrain dynamic query parts to allow-lists, and verify that attacker-controlled input can no longer change query semantics. Proof: AI plausible with source/sink/guard evidence.

## How To Read This Report

| Report field | What it means | How to use it |
| --- | --- | --- |
| Confidence | Evidence posture for the finding, not an exact probability | Use this as a triage signal, not a mathematical certainty |
| Confirmed by rule | Deterministic analysis proved the issue from code structure | Highest confidence |
| Validated by AI review | AI found the issue and verifier or skeptic review also supported it | Strong signal, but not rule-proven |
| Finder-only AI review | The finder reported the issue, but verifier and skeptic were not triggered or were unavailable | Treat as model-backed evidence, not independent validation |
| Finder high confidence, not independently verified | The finder score is high, but no verifier or skeptic pass is present in the audit trail | Useful triage signal; validate important fixes against the code |
| Partially validated | Some supporting evidence exists, but verification was incomplete | Review before acting |
| Needs manual review | Evidence is weak, incomplete, or low-confidence | Do not treat as confirmed yet |
| AI signal | Qualitative band plus final raw confidence from the model review trail | Use with the evidence label; the percentage is model confidence, not proof |
| Impact | How serious the damage could be if exploited | Business/security severity |
| Likelihood | How likely exploitation is from the observed code | Exploitability estimate |
| Risk score | Overall priority if the finding is real | Use this to prioritize fixes |
| Evidence confidence | Rule proof or qualitative AI signal for the detection | Separate from risk score |

## Scan Facts

- Files scanned: 1
- Files with findings: 1
- Total findings: 1
- Static findings: 0
- AI findings needing manual review: 0
- Confidence posture: 1 cross-checked
- Engine evidence: Structured contracts: 1/1 | confirmed: 1 | missing guards: 1 | deterministic gaps: 0 | AI without contract: 0
- Proof posture: static proven: 0 | AI plausible: 1 | counter-evidence: 0 | unproven extras: 0

## AI Usage

- Provider/model mix: azure-foundry / test-foundry-deployment-secondary
- AI requests: 3
- Total AI tokens: 62
- Estimated cost: not yet available

## Coverage And Context

- Coverage: Normal for the current provider and runtime state
- Knowledge sources: Fresh packs (1)
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5
- Project context: inline project contract
- Errors: 0
- Scan warnings: 0"
`);
        jest.useRealTimers();
    });

});
