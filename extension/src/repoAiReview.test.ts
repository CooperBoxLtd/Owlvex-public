import { applyRepoAiReviewSupport, buildRepoAiReviewPrompt, extractRepoAiSnippet, parseRepoAiReviewResponse, selectRepoAiCandidateRefs, summarizeRepoAiResults } from './repoAiReview';
import { ScanResult } from './scanner/scanEngine';

function buildResult(overrides?: Partial<ScanResult>): ScanResult {
    return {
        scanId: 'scan-1',
        score: 9,
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

describe('repoAiReview helpers', () => {
    it('selects top AI findings only', () => {
        const refs = selectRepoAiCandidateRefs([
            {
                path: 'a.js',
                result: buildResult({
                    findings: [
                        {
                            id: 'det',
                            line: 1,
                            lineEnd: 1,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            ruleCode: 'GR-001',
                            title: 'Deterministic issue',
                            explanation: 'x',
                            threat: 'x',
                            fix: 'x',
                            confidence: 1,
                            provenance: 'deterministic',
                            scanTier: 'STATIC',
                            riskScore: 10,
                        },
                        {
                            id: 'ai-low',
                            line: 2,
                            lineEnd: 2,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            ruleCode: 'AI-1',
                            title: 'AI issue',
                            explanation: 'x',
                            threat: 'x',
                            fix: 'x',
                            confidence: 0.7,
                            provenance: 'ai',
                            scanTier: 'TARGETED_AI',
                            riskScore: 5,
                        },
                    ],
                }),
            },
            {
                path: 'b.js',
                result: buildResult({
                    findings: [
                        {
                            id: 'ai-high',
                            line: 4,
                            lineEnd: 4,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            ruleCode: 'AI-2',
                            title: 'AI higher issue',
                            explanation: 'x',
                            threat: 'x',
                            fix: 'x',
                            confidence: 0.8,
                            provenance: 'ai',
                            scanTier: 'TARGETED_AI',
                            riskScore: 9,
                        },
                    ],
                }),
            },
        ], 2);

        expect(refs).toHaveLength(2);
        expect(refs[0].finding.id).toBe('ai-high');
        expect(refs[1].finding.id).toBe('ai-low');
    });

    it('extracts a numbered snippet around the finding', () => {
        const snippet = extractRepoAiSnippet(['one', 'two', 'three', 'four', 'five'].join('\n'), {
            id: 'f1',
            line: 3,
            lineEnd: 3,
            severity: 'MEDIUM',
            framework: 'OWASP',
            ruleCode: 'AI-1',
            title: 'Issue',
            explanation: 'x',
            threat: 'x',
            fix: 'x',
            confidence: 0.7,
            provenance: 'ai',
        }, 1);

        expect(snippet).toContain('2 | two');
        expect(snippet).toContain('3 | three');
        expect(snippet).toContain('4 | four');
    });

    it('builds a repo review prompt with scope and context', () => {
        const prompt = buildRepoAiReviewPrompt({
            scopeLabel: 'Folder: benchmark-app',
            projectContext: 'All reads must be tenant scoped.',
            fileSummaries: summarizeRepoAiResults([
                {
                    path: 'db.js',
                    result: buildResult({
                        findings: [{
                            id: 'f1',
                            line: 10,
                            lineEnd: 10,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            ruleCode: 'AI-1',
                            title: 'Issue',
                            explanation: 'x',
                            threat: 'x',
                            fix: 'x',
                            confidence: 0.8,
                            provenance: 'ai',
                            scanTier: 'TARGETED_AI',
                            riskScore: 9,
                        }],
                    }),
                },
            ]),
            candidates: [{
                reviewId: 'db.js#f1',
                path: 'db.js',
                resultIndex: 0,
                findingIndex: 0,
                finding: {
                    id: 'f1',
                    line: 10,
                    lineEnd: 10,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'AI-1',
                    title: 'Issue',
                    explanation: 'x',
                    threat: 'x',
                    fix: 'x',
                    confidence: 0.8,
                    provenance: 'ai',
                    scanTier: 'TARGETED_AI',
                    riskScore: 9,
                    corroboration: 'PARTIAL',
                },
                snippet: '10 | const q = sql;',
            }],
        });

        expect(prompt).toContain('Folder: benchmark-app');
        expect(prompt).toContain('All reads must be tenant scoped.');
        expect(prompt).toContain('"id": "db.js#f1"');
    });

    it('keeps the repo ai prompt shape bounded and stable', () => {
        const prompt = buildRepoAiReviewPrompt({
            scopeLabel: 'Selected files: 2 file(s)',
            projectContext: 'JWT verification happens only in auth middleware.',
            fileSummaries: [{
                path: 'src/lib/tokens.js',
                fileRiskScore: 9,
                findings: 2,
                topFindingTitle: 'Weak JWT validation',
                scanTiers: ['TARGETED_AI'],
            }],
            candidates: [{
                reviewId: 'src/lib/tokens.js#f1',
                path: 'src/lib/tokens.js',
                resultIndex: 0,
                findingIndex: 0,
                finding: {
                    id: 'f1',
                    line: 17,
                    lineEnd: 17,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'AI-1',
                    title: 'Weak JWT validation',
                    explanation: 'The token is decoded without verification.',
                    threat: 'Attackers may tamper with token claims.',
                    fix: 'Verify JWT signatures and claims before trusting them.',
                    confidence: 0.84,
                    provenance: 'ai',
                    scanTier: 'TARGETED_AI',
                    corroboration: 'PARTIAL',
                    canonicalId: 'owlvex.issue.weak_jwt_validation.001',
                    riskScore: 9,
                },
                snippet: '17 | const claims = decodeWithoutVerify(token);',
            }],
        });

        expect(prompt).toMatchInlineSnapshot(`
"You are Owlvex Repo AI review.
Review only the candidate findings below using broader repo context across the scanned files.
Support a candidate only when cross-file or architectural context materially strengthens the claim.
Do not invent new findings. Do not suppress findings just because the snippet is incomplete.
Return JSON only in this shape:
{"reviews":[{"id":"candidate-id","verdict":"support|reject|unclear","reason":"short reason"}]}

Scope:
Selected files: 2 file(s)

Project context:
JWT verification happens only in auth middleware.

Scanned file summaries:
[
  {
    "path": "src/lib/tokens.js",
    "fileRiskScore": 9,
    "findings": 2,
    "topFindingTitle": "Weak JWT validation",
    "scanTiers": [
      "TARGETED_AI"
    ]
  }
]

Candidate findings:
[
  {
    "id": "src/lib/tokens.js#f1",
    "path": "src/lib/tokens.js",
    "line": 17,
    "line_end": 17,
    "title": "Weak JWT validation",
    "canonical_id": "owlvex.issue.weak_jwt_validation.001",
    "risk_score": 9,
    "corroboration": "PARTIAL",
    "explanation": "The token is decoded without verification.",
    "snippet": "17 | const claims = decodeWithoutVerify(token);"
  }
]"
`);
    });

    it('parses fenced JSON review responses', () => {
        const reviews = parseRepoAiReviewResponse('```json\n{"reviews":[{"id":"a#1","verdict":"support","reason":"cross-file policy missing"}]}\n```');
        expect(reviews).toEqual([{ id: 'a#1', verdict: 'support', reason: 'cross-file policy missing' }]);
    });

    it('promotes only supported findings to repo ai', () => {
        const results = [
            {
                path: 'db.js',
                result: buildResult({
                    findings: [{
                        id: 'f1',
                        line: 10,
                        lineEnd: 10,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        ruleCode: 'AI-1',
                        title: 'Issue',
                        explanation: 'x',
                        threat: 'x',
                        fix: 'x',
                        confidence: 0.8,
                        provenance: 'ai',
                        scanTier: 'TARGETED_AI',
                        corroboration: 'PARTIAL',
                        riskScore: 9,
                    }],
                }),
            },
        ];
        const refs = selectRepoAiCandidateRefs(results);
        const updated = applyRepoAiReviewSupport(results, refs, [{ id: refs[0].reviewId, verdict: 'support' }]);

        expect(updated[0].result.findings[0].scanTier).toBe('REPO_AI');
        expect(updated[0].result.findings[0].corroboration).toBe('CORROBORATED');
        expect(updated[0].result.findings[0].confidence).toBe(0.9);
    });
});
