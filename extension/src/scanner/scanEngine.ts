import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { LicenceManager } from '../licence/licenceManager';
import { ProviderRegistry } from '../providers/registry';
import { CanonicalMappings, getCanonicalIssueById, resolveIssue } from '../frameworks/issueResolver';
import { buildGroundedRemediationPromptContext } from '../frameworks/remediationResolver';
import { getIssueFamilyDefinition } from '../frameworks/issueCatalog';
import { DeterministicScanner } from './deterministicScanner';
import type { RulePackRuntimeContext } from '../packs/packRuntime';
import { PROFILE } from '../profile';

export interface Finding {
    id: string;
    line: number;
    lineEnd: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    framework: string;
    ruleCode: string;
    title: string;
    explanation: string;
    threat: string;
    fix: string;
    confidence: number;
    /** How this finding was produced. Deterministic findings have confidence = 1. */
    provenance?: 'deterministic' | 'ai';
    canonicalId?: string;
    canonicalTitle?: string;
    canonicalCategory?: string;
    canonicalFamily?: string;
    canonicalFamilyLabel?: string;
    stride?: string[];
    mappings?: CanonicalMappings;
    matchedSignals?: string[];
    resolverConfidence?: number;
    likelihood?: 'LOW' | 'MEDIUM' | 'HIGH';
    likelihoodReasons?: string[];
    riskScore?: number;
}

export interface ScanResult {
    scanId: string;
    score: number;
    summary: string;
    findings: Finding[];
    positives: string[];
    metrics: { critical: number; high: number; medium: number; low: number };
    durationMs: number;
    model: string;
    provider: string;
    warnings: string[];
    packContext?: RulePackRuntimeContext;
}

export interface ScanDocumentOptions {
    forceDeterministicOnly?: boolean;
    deterministicOnlyReason?: string;
}

interface PromptContext {
    templateId?: string;
    systemPrompt: string;
}

interface SeverityMetrics {
    critical: number;
    high: number;
    medium: number;
    low: number;
}

type FindingSeverity = Finding['severity'];
type FindingLikelihood = NonNullable<Finding['likelihood']>;

const RISK_MATRIX: Record<FindingSeverity, Record<FindingLikelihood, number>> = {
    LOW: { LOW: 1, MEDIUM: 2, HIGH: 4 },
    MEDIUM: { LOW: 3, MEDIUM: 5, HIGH: 7 },
    HIGH: { LOW: 5, MEDIUM: 8, HIGH: 9 },
    CRITICAL: { LOW: 8, MEDIUM: 9, HIGH: 10 },
};

const SEVERITY_PENALTY: Record<FindingSeverity, number> = {
    LOW: 0.5,
    MEDIUM: 1.5,
    HIGH: 2.5,
    CRITICAL: 4,
};

const LIKELIHOOD_MULTIPLIER: Record<FindingLikelihood, number> = {
    LOW: 0.75,
    MEDIUM: 1,
    HIGH: 1.5,
};

function buildMetrics(findings: Finding[]): SeverityMetrics {
    return {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
    };
}

function normalizeLikelihood(value: unknown): FindingLikelihood | undefined {
    const normalized = String(value ?? '').trim().toUpperCase();
    if (normalized === 'LOW' || normalized === 'MEDIUM' || normalized === 'HIGH') {
        return normalized;
    }

    return undefined;
}

function getFindingLikelihood(finding: Finding): FindingLikelihood {
    return normalizeLikelihood(finding.likelihood) ?? 'MEDIUM';
}

function computeFindingRiskScore(severity: FindingSeverity, likelihood: FindingLikelihood): number {
    return RISK_MATRIX[severity][likelihood];
}

function computeFindingPenalty(finding: Finding): number {
    const likelihood = getFindingLikelihood(finding);
    return SEVERITY_PENALTY[finding.severity] * LIKELIHOOD_MULTIPLIER[likelihood];
}

function calculateScoreFromFindings(findings: Finding[]): number {
    const penalty = findings.reduce((total, finding) => total + computeFindingPenalty(finding), 0);
    return Math.max(0, Number((10 - penalty).toFixed(1)));
}

function enrichFindingRisk(finding: Finding): Finding {
    const likelihood = getFindingLikelihood(finding);
    return {
        ...finding,
        likelihood,
        riskScore: computeFindingRiskScore(finding.severity, likelihood),
    };
}

function summarizeFindings(findings: Finding[], fallbackSummary: string): string {
    if (!findings.length) {
        return fallbackSummary || 'No findings detected.';
    }

    const severityOrder: Finding['severity'][] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const highestSeverity = severityOrder.find(severity => findings.some(f => f.severity === severity)) ?? 'LOW';
    const highestSeverityCount = findings.filter(f => f.severity === highestSeverity).length;
    const families = [...new Set(
        findings
            .map(f => f.canonicalFamilyLabel || f.canonicalFamily)
            .filter((value): value is string => Boolean(value)),
    )];

    const highestRisk = findings
        .slice()
        .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0];

    const parts = [`${findings.length} finding(s) detected, led by ${highestSeverityCount} ${highestSeverity.toLowerCase()}-severity issue(s).`];

    if (highestRisk) {
        parts.push(
            `Highest contextual risk: ${highestRisk.severity.toLowerCase()} impact x ${getFindingLikelihood(highestRisk).toLowerCase()} likelihood = ${(highestRisk.riskScore ?? 0)}/10.`,
        );
    }

    if (families.length) {
        parts.push(`Issue families: ${families.join(', ')}.`);
    }

    return parts.join(' ');
}

function normalizeStringList(value: unknown): string[] | undefined {
    if (Array.isArray(value)) {
        return value
            .map(item => String(item).trim())
            .filter(Boolean);
    }

    if (typeof value === 'string') {
        return value
            .split(/[,\n]/)
            .map(item => item.trim())
            .filter(Boolean);
    }

    return undefined;
}

function normalizeMappings(value: any): CanonicalMappings | undefined {
    if (!value || typeof value !== 'object') {
        return undefined;
    }

    return {
        cwe: normalizeStringList(value.cwe) ?? [],
        owasp: normalizeStringList(value.owasp) ?? [],
        apiOwasp: normalizeStringList(value.api_owasp ?? value.apiOwasp) ?? [],
        attack: normalizeStringList(value.attack) ?? [],
        capec: normalizeStringList(value.capec) ?? [],
        nist: normalizeStringList(value.nist) ?? [],
    };
}

function buildDeterministicGroundingContext(findings: Finding[]): string {
    if (!findings.length) {
        return 'No deterministic findings were proven for this file. AI may analyze uncovered regions, but it must stay evidence-based.';
    }

    return [
        'Deterministic findings already proven for this file:',
        ...findings.map((finding, index) => {
            const family = finding.canonicalFamilyLabel || finding.canonicalFamily || 'Unclassified';
            return `${index + 1}. line ${finding.line}-${finding.lineEnd} | ${finding.ruleCode} | ${finding.title} | canonical=${finding.canonicalId ?? 'unknown'} | family=${family}`;
        }),
        'Do not emit a second competing finding for the same code region.',
        'If a deterministic finding exists for a region, only enrich it consistently or stay silent for that region.',
    ].join('\n');
}

function findingsOverlap(left: Finding, right: Finding): boolean {
    const leftStart = Math.min(left.line, left.lineEnd ?? left.line);
    const leftEnd = Math.max(left.line, left.lineEnd ?? left.line);
    const rightStart = Math.min(right.line, right.lineEnd ?? right.line);
    const rightEnd = Math.max(right.line, right.lineEnd ?? right.line);

    return leftStart <= (rightEnd + 2) && rightStart <= (leftEnd + 2);
}

function sameCanonicalRegion(det: Finding, ai: Finding): boolean {
    return findingsOverlap(det, ai)
        || (!!det.canonicalId && det.canonicalId === ai.canonicalId)
        || (!!det.ruleCode && det.ruleCode === ai.ruleCode && findingsOverlap(det, ai));
}

function conflictsWithDeterministic(det: Finding, ai: Finding): boolean {
    if (!sameCanonicalRegion(det, ai)) {
        return false;
    }

    if (det.canonicalId && ai.canonicalId && det.canonicalId === ai.canonicalId) {
        return true;
    }

    if (det.ruleCode && ai.ruleCode && det.ruleCode === ai.ruleCode) {
        return true;
    }

    if (det.canonicalFamily && ai.canonicalFamily && det.canonicalFamily !== ai.canonicalFamily) {
        return true;
    }

    if (det.canonicalFamilyLabel && ai.canonicalFamilyLabel && det.canonicalFamilyLabel !== ai.canonicalFamilyLabel) {
        return true;
    }

    return true;
}

function mergeDeterministicAndAiFindings(deterministicFindings: Finding[], aiFindings: Finding[]): Finding[] {
    if (!deterministicFindings.length) {
        return aiFindings;
    }

    const filteredAiFindings = aiFindings.filter(ai =>
        !deterministicFindings.some(det => conflictsWithDeterministic(det, ai)),
    );

    return [...deterministicFindings, ...filteredAiFindings];
}

function isRateLimitError(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error ?? '');
    return /\b429\b/.test(message) || /rate limit/i.test(message);
}

function extractRetryAfterMs(error: unknown): number | undefined {
    const message = error instanceof Error ? error.message : String(error ?? '');
    const retryAfterSecondsMatch = message.match(/retry-after:\s*(\d+(?:\.\d+)?)/i);
    if (retryAfterSecondsMatch) {
        return Math.max(0, Math.ceil(Number(retryAfterSecondsMatch[1]) * 1000));
    }

    const retryAfterMsMatch = message.match(/retry-after-ms:\s*(\d+)/i);
    if (retryAfterMsMatch) {
        return Math.max(0, Number(retryAfterMsMatch[1]));
    }

    return undefined;
}

async function sleep(ms: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, ms));
}

export class ScanEngine {
    private readonly deterministicScanner = new DeterministicScanner();
    private readonly licenceValidationCache = new Map<string, Promise<void>>();
    private readonly promptCache = new Map<string, Promise<PromptContext>>();

    constructor(
        private readonly licenceMgr: LicenceManager,
        private readonly registry: ProviderRegistry,
    ) {}

    async scanDocument(document: vscode.TextDocument, options?: ScanDocumentOptions): Promise<ScanResult> {
        const config = vscode.workspace.getConfiguration(PROFILE.configSection);
        const apiUrl = config.get<string>('apiUrl') ?? PROFILE.defaultApiUrl;
        const frameworks = config.get<string[]>('frameworks', ['OWASP']);
        const severityThreshold = config.get<string>('severityThreshold', 'MEDIUM');
        const teamContext = config.get<string>('teamContext', '');
        const language = this._detectLanguage(document);
        const provider = this.registry.getActive();

        const code = document.getText();
        const deterministicFindings = this.deterministicScanner
            .scan(code, document.languageId)
            .map(f => this._resolveCanonicalFinding({ ...f, provenance: 'deterministic' } as Finding))
            .map(f => enrichFindingRisk(f));

        if (options?.forceDeterministicOnly || options?.deterministicOnlyReason) {
            return this._buildDeterministicOnlyResult(
                deterministicFindings,
                options?.deterministicOnlyReason ?? 'AI enrichment skipped for this scan.',
                provider,
            );
        }

        const licenceKey = await this.licenceMgr.getKey();
        if (!licenceKey) {
            return this._buildDeterministicOnlyResult(
                deterministicFindings,
                'Owlvex backend unavailable: no licence key configured. Returning deterministic-only results.',
                provider,
            );
        }

        let promptContext: PromptContext;
        try {
            await this._validateLicenceCached(apiUrl, licenceKey);
            promptContext = await this._getPromptContextCached({
                apiUrl,
                licenceKey,
                frameworks,
                language,
                model: provider.selectedModel,
                severityThreshold,
                teamContext,
            });
        } catch (error: any) {
            return this._buildDeterministicOnlyResult(
                deterministicFindings,
                `Owlvex backend unavailable: ${error.message}`,
                provider,
            );
        }
        const systemPrompt = promptContext.systemPrompt;


        // Run deterministic scanner first — high-confidence, zero-cost findings.

        const start = Date.now();

        let aiResponse;
        const groundedRemediationContext = buildGroundedRemediationPromptContext();
        try {
            aiResponse = await this._completeWithRateLimitHandling(provider, {
                systemPrompt,
                userMessage: `Analyse this ${language} code.\nResolve each finding to the closest Owlvex canonical issue when possible.\nInclude optional fields issue_id, stride, mappings, matched_signals, likelihood, and likelihood_reasons if you can determine them.\nTreat severity as impact. Use likelihood only for exploitability in this specific code context, and keep it evidence-based: LOW, MEDIUM, or HIGH.\nUse grounded Owlvex remediation when a canonical issue below applies; adapt it to the local code instead of inventing a different remediation standard.\nDeterministic findings are confirmed structural violations. AI-only findings should stay evidence-based and avoid overclaiming.\n${buildDeterministicGroundingContext(deterministicFindings)}\n${groundedRemediationContext ? `\nGrounded remediation guidance:\n${groundedRemediationContext}\n` : ''}\nCode:\n\n${code}`,
                model: provider.selectedModel,
                temperature: 0.1,
            });
        } catch (error: any) {
            return this._buildDeterministicOnlyResult(
                deterministicFindings,
                `AI provider unavailable: ${error.message}`,
                provider,
            );
        }

        const durationMs = Date.now() - start;
        let parsed;
        try {
            parsed = this._parseAIResponse(aiResponse.content);
        } catch (error: any) {
            return this._buildDeterministicOnlyResult(
                deterministicFindings,
                `AI response unusable: ${error.message}`,
                provider,
            );
        }

        const fileHash = crypto.createHash('sha256').update(code).digest('hex');
        const fileName = document.fileName.split(/[/\\]/).pop() ?? 'unknown';

        // Merge deterministic findings with AI findings.
        // Deterministic findings lead — they are high-confidence and zero-cost.
        // Deduplicate by canonicalId + line to avoid doubling up when the AI
        // also found the same issue at the same location.
        const allFindings = mergeDeterministicAndAiFindings(deterministicFindings, parsed.findings)
            .map(finding => enrichFindingRisk(finding));
        const mergedMetrics = buildMetrics(allFindings);
        const calculatedScore = calculateScoreFromFindings(allFindings);
        const summary = summarizeFindings(allFindings, parsed.summary);
        let scanId = crypto.randomUUID();
        const warnings: string[] = [];

        try {
            const recordRes = await fetch(`${apiUrl}/v1/scans/record`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Licence-Key': licenceKey,
                },
                body: JSON.stringify({
                    file_name: fileName,
                    file_hash: fileHash,
                    language,
                    model: provider.selectedModel,
                    provider: provider.id,
                    frameworks,
                    score: calculatedScore,
                    findings_summary: mergedMetrics,
                    finding_count: allFindings.length,
                    token_count: aiResponse.tokenCount,
                    duration_ms: durationMs,
                    prompt_id: promptContext.templateId,
                    prompt_snapshot: systemPrompt,
                }),
            });

            if (!recordRes.ok) {
                warnings.push(await this._readErrorResponse(recordRes, 'Failed to record scan'));
            } else {
                const recordData = await this._readJsonResponse(recordRes, 'Scan recorder returned invalid JSON');
                scanId = recordData.scan_id ?? scanId;
            }
        } catch (error: any) {
            warnings.push(`Failed to record scan: ${error.message}`);
        }

        return {
            scanId,
            score: calculatedScore,
            summary,
            findings: allFindings,
            positives: parsed.positives,
            metrics: mergedMetrics,
            durationMs,
            model: provider.selectedModel,
            provider: provider.id,
            warnings,
        };
    }

    private _buildDeterministicOnlyResult(
        deterministicFindings: Finding[],
        warning: string,
        provider: { id: string; selectedModel: string },
    ): ScanResult {
        const metrics = buildMetrics(deterministicFindings);
        const score = calculateScoreFromFindings(deterministicFindings);
        const summary = deterministicFindings.length
            ? summarizeFindings(
                deterministicFindings,
                `${deterministicFindings.length} deterministic finding(s) returned while backend or AI services were unavailable.`,
            )
            : 'No deterministic findings. Backend or AI services were unavailable, so Owlvex returned local-only results.';

        return {
            scanId: crypto.randomUUID(),
            score,
            summary,
            findings: deterministicFindings,
            positives: [],
            metrics,
            durationMs: 0,
            model: `${provider.selectedModel} (deterministic-only)`,
            provider: provider.id,
            warnings: [warning],
        };
    }

    private async _completeWithRateLimitHandling(
        provider: { complete(req: { systemPrompt: string; userMessage: string; model: string; temperature: number }): Promise<any> },
        req: { systemPrompt: string; userMessage: string; model: string; temperature: number },
    ): Promise<any> {
        const maxAttempts = 3;

        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            try {
                return await provider.complete(req);
            } catch (error) {
                if (!isRateLimitError(error) || attempt === maxAttempts) {
                    throw error;
                }

                const retryAfterMs = extractRetryAfterMs(error);
                const backoffMs = retryAfterMs ?? (1500 * (2 ** (attempt - 1)));
                await sleep(backoffMs);
            }
        }

        throw new Error('AI provider unavailable after retries.');
    }

    private async _validateLicenceCached(apiUrl: string, licenceKey: string): Promise<void> {
        const cacheKey = `${apiUrl}::${licenceKey}`;
        const cached = this.licenceValidationCache.get(cacheKey);
        if (cached) {
            await cached;
            return;
        }

        const validationPromise = this.licenceMgr.validate(apiUrl).then(() => undefined);
        this.licenceValidationCache.set(cacheKey, validationPromise);

        try {
            await validationPromise;
        } catch (error) {
            this.licenceValidationCache.delete(cacheKey);
            throw error;
        }
    }

    private async _getPromptContextCached(params: {
        apiUrl: string;
        licenceKey: string;
        frameworks: string[];
        language: string;
        model: string;
        severityThreshold: string;
        teamContext: string;
    }): Promise<PromptContext> {
        const cacheKey = JSON.stringify({
            apiUrl: params.apiUrl,
            frameworks: [...params.frameworks].sort(),
            language: params.language,
            model: params.model,
            severityThreshold: params.severityThreshold,
            teamContext: params.teamContext,
        });
        const cached = this.promptCache.get(cacheKey);
        if (cached) {
            return cached;
        }

        const promptPromise = this._fetchPromptContext(params);
        this.promptCache.set(cacheKey, promptPromise);

        try {
            return await promptPromise;
        } catch (error) {
            this.promptCache.delete(cacheKey);
            throw error;
        }
    }

    private async _fetchPromptContext(params: {
        apiUrl: string;
        licenceKey: string;
        frameworks: string[];
        language: string;
        model: string;
        severityThreshold: string;
        teamContext: string;
    }): Promise<PromptContext> {
        const promptRes = await fetch(`${params.apiUrl}/v1/prompts/build`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Licence-Key': params.licenceKey,
            },
            body: JSON.stringify({
                frameworks: params.frameworks,
                language: params.language,
                model: params.model,
                severity_threshold: params.severityThreshold,
                team_context: params.teamContext,
            }),
        });

        if (!promptRes.ok) {
            throw new Error(await this._readErrorResponse(promptRes, 'Failed to fetch prompt'));
        }

        const promptData = await this._readJsonResponse(promptRes, 'Prompt builder returned invalid JSON');
        return {
            templateId: promptData.template_id,
            systemPrompt: promptData.system_prompt,
        };
    }

    private async _readJsonResponse(res: Response, fallbackMessage: string): Promise<any> {
        const text = await res.text();
        try {
            return JSON.parse(text);
        } catch {
            const snippet = text.trim().slice(0, 180);
            throw new Error(snippet ? `${fallbackMessage}: ${snippet}` : fallbackMessage);
        }
    }

    private async _readErrorResponse(res: Response, prefix: string): Promise<string> {
        const text = await res.text();
        if (!text.trim()) {
            return `${prefix}: HTTP ${res.status}`;
        }

        try {
            const parsed = JSON.parse(text);
            return parsed?.detail ? `${prefix}: ${parsed.detail}` : `${prefix}: HTTP ${res.status}`;
        } catch {
            return `${prefix}: ${text.trim().slice(0, 180)}`;
        }
    }

    private _detectLanguage(doc: vscode.TextDocument): string {
        const langMap: Record<string, string> = {
            'typescript': 'typescript',
            'javascript': 'javascript',
            'python': 'python',
            'java': 'java',
            'csharp': 'csharp',
            'cpp': 'cpp',
            'go': 'go',
            'rust': 'rust',
            'php': 'php',
            'ruby': 'ruby',
        };
        return langMap[doc.languageId] ?? doc.languageId;
    }

    private _parseAIResponse(raw: string): {
        score: number;
        summary: string;
        findings: Finding[];
        positives: string[];
        metrics: { critical: number; high: number; medium: number; low: number };
    } {
        const cleaned = raw.replace(/^```(?:json)?\n?/m, '').replace(/\n?```$/m, '').trim();

        try {
            const data = JSON.parse(cleaned);
            return {
                score: data.score ?? 5,
                summary: data.summary ?? '',
                findings: (data.findings ?? []).map((f: any) => ({
                    id: f.id ?? crypto.randomUUID(),
                    line: f.line ?? 1,
                    lineEnd: f.line_end ?? f.line ?? 1,
                    severity: f.severity ?? 'MEDIUM',
                    framework: f.framework ?? 'OWASP',
                    ruleCode: f.rule_code ?? '',
                    title: f.title ?? '',
                    explanation: f.explanation ?? '',
                    threat: f.threat ?? '',
                    fix: f.fix ?? '',
                    confidence: f.confidence ?? 0.8,
                    provenance: 'ai' as const,
                    canonicalId: f.issue_id,
                    stride: normalizeStringList(f.stride),
                    mappings: normalizeMappings(f.mappings),
                    matchedSignals: normalizeStringList(f.matched_signals),
                    likelihood: normalizeLikelihood(f.likelihood),
                    likelihoodReasons: normalizeStringList(f.likelihood_reasons ?? f.likelihoodReasons ?? f.context_reasons),
                })).map((finding: Finding) => this._resolveCanonicalFinding(finding)),
                positives: data.positives ?? [],
                metrics: data.metrics ?? { critical: 0, high: 0, medium: 0, low: 0 },
            };
        } catch {
            throw new Error('AI response could not be parsed as JSON');
        }
    }

    private _resolveCanonicalFinding(finding: Finding): Finding {
        if (finding.canonicalId) {
            const canonicalIssue = getCanonicalIssueById(finding.canonicalId);
            if (canonicalIssue) {
                return {
                    ...finding,
                    canonicalTitle: canonicalIssue.title,
                    canonicalCategory: canonicalIssue.category,
                    canonicalFamily: canonicalIssue.family,
                    canonicalFamilyLabel: getIssueFamilyDefinition(canonicalIssue.family)?.label,
                    stride: finding.stride ?? canonicalIssue.stride,
                    mappings: finding.mappings ?? canonicalIssue.mappings,
                };
            }
        }

        const resolved = resolveIssue(finding);
        if (!resolved) {
            return finding;
        }

        return {
            ...finding,
            canonicalId: finding.canonicalId ?? resolved.issue.id,
            canonicalTitle: resolved.issue.title,
            canonicalCategory: resolved.issue.category,
            canonicalFamily: resolved.issue.family,
            canonicalFamilyLabel: getIssueFamilyDefinition(resolved.issue.family)?.label,
            stride: finding.stride ?? resolved.issue.stride,
            mappings: finding.mappings ?? resolved.issue.mappings,
            matchedSignals: finding.matchedSignals ?? resolved.matchedSignals,
            resolverConfidence: resolved.confidence,
        };
    }
}
