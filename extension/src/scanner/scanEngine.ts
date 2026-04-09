import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { LicenceManager } from '../licence/licenceManager';
import { ProviderRegistry } from '../providers/registry';
import { CanonicalMappings, resolveIssue } from '../frameworks/issueResolver';
import { getIssueFamilyDefinition } from '../frameworks/issueCatalog';

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
    constructor(
        private readonly licenceMgr: LicenceManager,
        private readonly registry: ProviderRegistry,
    ) {}

    async scanDocument(document: vscode.TextDocument): Promise<ScanResult> {
        const config = vscode.workspace.getConfiguration('owlvex');
        const apiUrl = config.get<string>('apiUrl', 'http://owlvex.ml30.local');
        const frameworks = config.get<string[]>('frameworks', ['OWASP']);
        const severityThreshold = config.get<string>('severityThreshold', 'MEDIUM');
        const teamContext = config.get<string>('teamContext', '');

        const licenceKey = await this.licenceMgr.getKey();
        if (!licenceKey) {
            throw new Error('No licence key. Run "Owlvex: Enter Licence Key".');
        }

        await this.licenceMgr.validate(apiUrl);

        const promptRes = await fetch(`${apiUrl}/v1/prompts/build`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Licence-Key': licenceKey,
            },
            body: JSON.stringify({
                frameworks,
                language: this._detectLanguage(document),
                model: this.registry.getActive().selectedModel,
                severity_threshold: severityThreshold,
                team_context: teamContext,
            }),
        });

        if (!promptRes.ok) {
            throw new Error(await this._readErrorResponse(promptRes, 'Failed to fetch prompt'));
        }

        const promptData = await this._readJsonResponse(promptRes, 'Prompt builder returned invalid JSON');
        const systemPrompt: string = promptData.system_prompt;

        const code = document.getText();
        const language = this._detectLanguage(document);
        const provider = this.registry.getActive();
        const start = Date.now();

        const aiResponse = await provider.complete({
            systemPrompt,
            userMessage: `Analyse this ${language} code.\nResolve each finding to the closest Owlvex canonical issue when possible.\nInclude optional fields issue_id, stride, mappings, and matched_signals if you can determine them.\n\nCode:\n\n${code}`,
            model: provider.selectedModel,
            temperature: 0.1,
        });

        const durationMs = Date.now() - start;
        const parsed = this._parseAIResponse(aiResponse.content);

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
                    prompt_id: promptData.template_id,
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
            score: parsed.score,
            summary: parsed.summary,
            findings: parsed.findings,
            positives: parsed.positives,
            metrics: parsed.metrics,
            durationMs,
            model: provider.selectedModel,
            provider: provider.id,
            warnings,
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
