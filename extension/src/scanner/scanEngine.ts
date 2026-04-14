import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { LicenceManager } from '../licence/licenceManager';
import { ProviderRegistry } from '../providers/registry';
import { CanonicalMappings, resolveIssue } from '../frameworks/issueResolver';
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

interface PromptContext {
    templateId?: string;
    systemPrompt: string;
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

export class ScanEngine {
    private readonly deterministicScanner = new DeterministicScanner();
    private readonly licenceValidationCache = new Map<string, Promise<void>>();
    private readonly promptCache = new Map<string, Promise<PromptContext>>();

    constructor(
        private readonly licenceMgr: LicenceManager,
        private readonly registry: ProviderRegistry,
    ) {}

    async scanDocument(document: vscode.TextDocument): Promise<ScanResult> {
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
            .map(f => this._resolveCanonicalFinding({ ...f, provenance: 'deterministic' } as Finding));

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
        try {
            aiResponse = await provider.complete({
                systemPrompt,
                userMessage: `Analyse this ${language} code.\nResolve each finding to the closest Owlvex canonical issue when possible.\nInclude optional fields issue_id, stride, mappings, and matched_signals if you can determine them.\n\nCode:\n\n${code}`,
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
                    score: parsed.score,
                    findings_summary: parsed.metrics,
                    finding_count: parsed.findings.length,
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

        // Merge deterministic findings with AI findings.
        // Deterministic findings lead — they are high-confidence and zero-cost.
        // Deduplicate by canonicalId + line to avoid doubling up when the AI
        // also found the same issue at the same location.
        const aiOnlyFindings = parsed.findings.filter(ai =>
            !deterministicFindings.some(det =>
                det.canonicalId === ai.canonicalId && det.line === ai.line,
            ),
        );
        const allFindings = [...deterministicFindings, ...aiOnlyFindings];
        const mergedMetrics = {
            critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
            high: allFindings.filter(f => f.severity === 'HIGH').length,
            medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
            low: allFindings.filter(f => f.severity === 'LOW').length,
        };

        return {
            scanId,
            score: parsed.score,
            summary: parsed.summary,
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
        const metrics = {
            critical: deterministicFindings.filter(f => f.severity === 'CRITICAL').length,
            high: deterministicFindings.filter(f => f.severity === 'HIGH').length,
            medium: deterministicFindings.filter(f => f.severity === 'MEDIUM').length,
            low: deterministicFindings.filter(f => f.severity === 'LOW').length,
        };
        const score = Math.max(0, 10 - (metrics.critical * 3) - (metrics.high * 2) - metrics.medium - (metrics.low * 0.5));
        const summary = deterministicFindings.length
            ? `${deterministicFindings.length} deterministic finding(s) returned while backend or AI services were unavailable.`
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
                })).map((finding: Finding) => this._resolveCanonicalFinding(finding)),
                positives: data.positives ?? [],
                metrics: data.metrics ?? { critical: 0, high: 0, medium: 0, low: 0 },
            };
        } catch {
            throw new Error('AI response could not be parsed as JSON');
        }
    }

    private _resolveCanonicalFinding(finding: Finding): Finding {
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
