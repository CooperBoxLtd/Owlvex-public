import * as vscode from 'vscode';
import { generateReportFromSnapshot } from './scanner/reportGenerator';
import { applyRepoAiReviewSupport, selectRepoAiCandidateRefs } from './repoAiReview';
import { ScanEngine, ScanResult } from './scanner/scanEngine';

function createJsonResponse(payload: unknown): Response {
    return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
    });
}

function buildResult(overrides: Partial<ScanResult> = {}): ScanResult {
    return {
        scanId: 'scan-1',
        score: 7,
        summary: 'summary',
        findings: [],
        projectContextSummary: 'none',
        frameworks: ['OWASP'],
        positives: [],
        metrics: { critical: 0, high: 0, medium: 0, low: 0 },
        durationMs: 1,
        model: 'model',
        provider: 'provider',
        warnings: [],
        ...overrides,
    };
}

describe('stability guardrails', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('keeps deterministic-only fallback findings in STATIC/PROVEN posture', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockRejectedValue(new Error('backend unavailable')),
        } as any;
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete: jest.fn(),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\cmd.js',
            getText: () => 'exec(`cat ${file}`);',
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('deterministic');
        expect(result.findings[0].scanTier).toBe('STATIC');
        expect(result.findings[0].confidenceTier).toBe('PROVEN');
        expect(result.findings[0].corroboration).toBe('PROVEN');
    });

    it('does not allow project context to upgrade AI findings into PROVEN when the issue remains AI-only', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: (key: string, defaultValue?: any) => {
                switch (key) {
                    case 'apiUrl':
                        return 'https://api.example.test';
                    case 'frameworks':
                        return ['OWASP'];
                    case 'severityThreshold':
                        return 'MEDIUM';
                    case 'teamContext':
                        return '';
                    case 'projectContext':
                        return 'Only finance-admin users may issue refunds.';
                    case 'projectContextFile':
                        return '';
                    default:
                        return defaultValue;
                }
            },
        });

        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const complete = jest.fn()
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 6.4,
                    summary: 'Potential missing finance-admin authorization detected.',
                    findings: [{
                        id: 'ai-finance-admin',
                        line: 2,
                        line_end: 2,
                        severity: 'MEDIUM',
                        framework: 'OWASP',
                        rule_code: 'A01-AUTHZ',
                        title: 'Missing finance-admin authorization on refund action',
                        explanation: 'The refund action is reachable without a visible finance-admin authorization gate.',
                        threat: 'Unauthorized users may trigger refund operations.',
                        fix: 'Require a finance-admin role check before calling the refund path.',
                        confidence: 0.88,
                        issue_id: 'owlvex.issue.missing_authorization.001',
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            })
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    reviews: [{ id: 'ai-finance-admin', verdict: 'support', reason: 'supported' }],
                }),
                tokenCount: 10,
            })
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    reviews: [{ id: 'ai-finance-admin', verdict: 'clear', reason: 'no contradiction' }],
                }),
                tokenCount: 10,
            });
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\refund.js',
            getText: () => 'function refund(req, res) { return billing.refund(req.body.invoiceId); }',
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.projectContextSummary).toContain('inline project contract');
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('ai');
        expect(result.findings[0].scanTier).toBe('TARGETED_AI');
        expect(result.findings[0].confidenceTier).toBe('PLAUSIBLE');
        expect(result.findings[0].corroboration).toBe('CORROBORATED');
        expect(result.findings[0].corroboration).not.toBe('PROVEN');
    });

    it('allows REPO_AI to promote only existing AI findings and not invent or retier deterministic ones', () => {
        const results = [{
            path: 'mixed.js',
            result: buildResult({
                findings: [
                    {
                        id: 'det-1',
                        line: 1,
                        lineEnd: 1,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        ruleCode: 'AC-001',
                        title: 'Deterministic issue',
                        explanation: 'x',
                        threat: 'x',
                        fix: 'x',
                        confidence: 1,
                        provenance: 'deterministic',
                        scanTier: 'STATIC',
                        confidenceTier: 'PROVEN',
                        corroboration: 'PROVEN',
                        riskScore: 9,
                    },
                    {
                        id: 'ai-1',
                        line: 5,
                        lineEnd: 5,
                        severity: 'MEDIUM',
                        framework: 'OWASP',
                        ruleCode: 'AI-1',
                        title: 'AI issue',
                        explanation: 'x',
                        threat: 'x',
                        fix: 'x',
                        confidence: 0.8,
                        provenance: 'ai',
                        scanTier: 'TARGETED_AI',
                        confidenceTier: 'PLAUSIBLE',
                        corroboration: 'PARTIAL',
                        riskScore: 5,
                    },
                ] as any,
            }),
        }];

        const refs = selectRepoAiCandidateRefs(results, 3);
        const updated = applyRepoAiReviewSupport(results, refs, [
            { id: refs[0].reviewId, verdict: 'support', reason: 'repo context supports it' },
            { id: 'invented#finding', verdict: 'support', reason: 'should be ignored' },
        ]);

        expect(updated[0].result.findings).toHaveLength(2);
        expect(updated[0].result.findings[0].scanTier).toBe('STATIC');
        expect(updated[0].result.findings[0].corroboration).toBe('PROVEN');
        expect(updated[0].result.findings[1].scanTier).toBe('REPO_AI');
        expect(updated[0].result.findings[1].corroboration).toBe('CORROBORATED');
    });

    it('keeps primary scan mode and scan-tier posture explicit in report output', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('const risky = true;'));
        const writeFile = vscode.workspace.fs.writeFile as jest.Mock;
        const snapshot = {
            targetLabel: 'demo',
            outputRoot: vscode.Uri.file('d:\\repo\\tools\\demo'),
            errors: [],
            results: [{
                uri: vscode.Uri.file('d:\\repo\\tools\\demo\\sample.js'),
                result: buildResult({
                    score: 9,
                    findings: [{
                        id: 'ai-1',
                        line: 3,
                        lineEnd: 3,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        ruleCode: 'AI-1',
                        title: 'Repo-supported issue',
                        explanation: 'x',
                        threat: 'x',
                        fix: 'x',
                        confidence: 0.9,
                        provenance: 'ai',
                        scanTier: 'REPO_AI',
                        confidenceTier: 'PLAUSIBLE',
                        corroboration: 'CORROBORATED',
                        riskScore: 9,
                    }] as any,
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    model: 'test-foundry-deployment-secondary',
                    provider: 'azure-foundry',
                }),
            }],
        };

        await generateReportFromSnapshot(snapshot.outputRoot, snapshot);

        const written = Buffer.from(writeFile.mock.calls[0][1]).toString('utf8');
        expect(written).toContain('- Analysis mode: Repo-context AI review');
        expect(written).toContain('- Analysis mix: repo_ai: 1');
        expect(written).toContain('- Evidence: corroborated: 1');
        expect(written).toContain('- Analysis mode: Repo-context AI review');
    });
});
