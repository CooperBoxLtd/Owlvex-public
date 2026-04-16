import { Finding, ScanResult } from './scanner/scanEngine';

export interface RepoAiCandidateRef {
    reviewId: string;
    path: string;
    resultIndex: number;
    findingIndex: number;
    finding: Finding;
}

export interface RepoAiCandidate extends RepoAiCandidateRef {
    snippet: string;
}

export interface RepoAiReviewSummary {
    path: string;
    fileRiskScore: number;
    findings: number;
    topFindingTitle: string;
    scanTiers: string[];
}

export interface RepoAiReview {
    id: string;
    verdict: 'support' | 'reject' | 'unclear';
    reason?: string;
}

export function selectRepoAiCandidateRefs(
    results: Array<{ path: string; result: ScanResult }>,
    limit = 3,
): RepoAiCandidateRef[] {
    const refs: RepoAiCandidateRef[] = [];

    results.forEach((item, resultIndex) => {
        item.result.findings.forEach((finding, findingIndex) => {
            if (finding.provenance !== 'ai') {
                return;
            }
            if (finding.scanTier === 'REPO_AI') {
                return;
            }

            refs.push({
                reviewId: `${item.path}#${finding.id}`,
                path: item.path,
                resultIndex,
                findingIndex,
                finding,
            });
        });
    });

    return refs
        .sort((left, right) => {
            const riskDelta = (right.finding.riskScore ?? 0) - (left.finding.riskScore ?? 0);
            if (riskDelta !== 0) {
                return riskDelta;
            }

            const confidenceDelta = (right.finding.confidence ?? 0) - (left.finding.confidence ?? 0);
            if (confidenceDelta !== 0) {
                return confidenceDelta;
            }

            return left.path.localeCompare(right.path);
        })
        .slice(0, limit);
}

export function extractRepoAiSnippet(text: string, finding: Finding, radius = 4): string {
    const lines = text.split(/\r?\n/);
    if (!lines.length) {
        return '';
    }

    const start = Math.max(0, Math.min(lines.length - 1, finding.line - 1 - radius));
    const end = Math.max(start, Math.min(lines.length, finding.lineEnd + radius));

    return lines
        .slice(start, end)
        .map((line, index) => `${start + index + 1} | ${line}`)
        .join('\n');
}

export function summarizeRepoAiResults(results: Array<{ path: string; result: ScanResult }>): RepoAiReviewSummary[] {
    return results.map(item => {
        const topFinding = item.result.findings
            .slice()
            .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0];
        const scanTiers = [...new Set(
            item.result.findings.map(finding => finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI')),
        )];

        return {
            path: item.path,
            fileRiskScore: item.result.score,
            findings: item.result.findings.length,
            topFindingTitle: topFinding?.title ?? 'none',
            scanTiers,
        };
    });
}

export function buildRepoAiReviewPrompt(params: {
    scopeLabel: string;
    projectContext: string;
    fileSummaries: RepoAiReviewSummary[];
    candidates: RepoAiCandidate[];
}): string {
    const candidatePayload = params.candidates.map(candidate => ({
        id: candidate.reviewId,
        path: candidate.path,
        line: candidate.finding.line,
        line_end: candidate.finding.lineEnd,
        title: candidate.finding.title,
        canonical_id: candidate.finding.canonicalId ?? '',
        risk_score: candidate.finding.riskScore ?? 0,
        corroboration: candidate.finding.corroboration ?? 'UNVERIFIED',
        explanation: candidate.finding.explanation,
        snippet: candidate.snippet,
    }));

    return `You are Owlvex Repo AI review.
Review only the candidate findings below using broader repo context across the scanned files.
Support a candidate only when cross-file or architectural context materially strengthens the claim.
Do not invent new findings. Do not suppress findings just because the snippet is incomplete.
Return JSON only in this shape:
{"reviews":[{"id":"candidate-id","verdict":"support|reject|unclear","reason":"short reason"}]}

Scope:
${params.scopeLabel}

Project context:
${params.projectContext || 'none'}

Scanned file summaries:
${JSON.stringify(params.fileSummaries, null, 2)}

Candidate findings:
${JSON.stringify(candidatePayload, null, 2)}`;
}

export function parseRepoAiReviewResponse(raw: string): RepoAiReview[] {
    const cleaned = raw.replace(/^```(?:json)?\n?/m, '').replace(/\n?```$/m, '').trim();
    const data = JSON.parse(cleaned);
    if (!Array.isArray(data.reviews)) {
        throw new Error('REPO_AI review response did not contain a reviews array');
    }

    return data.reviews
        .map((review: any) => ({
            id: String(review.id ?? '').trim(),
            verdict: String(review.verdict ?? '').trim().toLowerCase(),
            reason: typeof review.reason === 'string' ? review.reason.trim() : undefined,
        }))
        .filter((review: any) => review.id && ['support', 'reject', 'unclear'].includes(review.verdict));
}

export function applyRepoAiReviewSupport(
    results: Array<{ path: string; result: ScanResult }>,
    refs: RepoAiCandidateRef[],
    reviews: RepoAiReview[],
): Array<{ path: string; result: ScanResult }> {
    const supportedIds = new Set(
        reviews
            .filter(review => review.verdict === 'support')
            .map(review => review.id),
    );
    if (!supportedIds.size) {
        return results;
    }

    return results.map((item, resultIndex) => {
        const applicable = refs.filter(ref => ref.resultIndex === resultIndex && supportedIds.has(ref.reviewId));
        if (!applicable.length) {
            return item;
        }

        const updatedFindings = item.result.findings.map((finding, findingIndex) => {
            const match = applicable.find(ref => ref.findingIndex === findingIndex);
            if (!match) {
                return finding;
            }

            const corroboration: Finding['corroboration'] = finding.corroboration === 'PROVEN'
                ? 'PROVEN'
                : 'CORROBORATED';

            return {
                ...finding,
                scanTier: 'REPO_AI' as const,
                confidence: Math.max(finding.confidence ?? 0.8, 0.9),
                corroboration,
            };
        });

        return {
            ...item,
            result: {
                ...item.result,
                findings: updatedFindings,
            },
        };
    });
}
