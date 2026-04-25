import * as path from 'path';
import * as vscode from 'vscode';
import { getGroundedCheatSheetLabelsForIssueIds, resolveRemediationForFinding } from '../frameworks/remediationResolver';
import { describeRulePackRuntime, getRulePackModeLabel } from '../packs/packRuntime';
import { ScanResult } from './scanEngine';
import { FolderScanSummary } from './workspaceScanner';
import { formatFrameworkSummary } from '../frameworks/catalog';
import { PROFILE } from '../profile';

export interface ReportEntry {
    uri: vscode.Uri;
    result: ScanResult;
}

export interface ReportSnapshot {
    targetLabel: string;
    outputRoot: vscode.Uri;
    errors: string[];
    results: ReportEntry[];
}

export type ReportVariant = 'summary' | 'full';

export interface ReportGenerationOptions {
    variant?: ReportVariant;
}

function formatTimestamp(date: Date): string {
    const pad = (value: number) => String(value).padStart(2, '0');
    return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function escapeMarkdown(value: string): string {
    return value.replace(/\|/g, '\\|');
}

function escapeCodeFence(value: string): string {
    return value.replace(/```/g, '``\\`');
}

function looksLikeWindowsPath(value: string): boolean {
    return /^[a-zA-Z]:[\\/]/.test(value);
}

function formatReportPath(rootPath: string, filePath: string): string {
    const relative = looksLikeWindowsPath(rootPath) || looksLikeWindowsPath(filePath)
        ? path.win32.relative(rootPath, filePath)
        : path.relative(rootPath, filePath);

    return (relative || path.basename(filePath)).replace(/\\/g, '/');
}

function normalizeFrameworkCodes(frameworks?: string[]): Set<string> {
    return new Set((frameworks ?? []).map(value => String(value).trim().toUpperCase()).filter(Boolean));
}

function formatMappings(
    mappings: NonNullable<ScanResult['findings'][number]['mappings']> | undefined,
    frameworks?: string[],
): string {
    if (!mappings) return '';

    const enabled = normalizeFrameworkCodes(frameworks);
    const showAllSecurityMappings = enabled.size === 0;

    return ([
        ['CWE', mappings.cwe, enabled.has('CWE') || showAllSecurityMappings],
        ['OWASP', mappings.owasp, enabled.has('OWASP') || showAllSecurityMappings],
        ['API OWASP', mappings.apiOwasp, enabled.has('OWASP') || showAllSecurityMappings],
        ['ATT&CK', mappings.attack, enabled.has('MITRE') || showAllSecurityMappings],
        ['CAPEC', mappings.capec, enabled.has('MITRE') || enabled.has('CWE') || showAllSecurityMappings],
        ['NIST', mappings.nist, enabled.has('NIST') || showAllSecurityMappings],
    ] as Array<[string, string[], boolean]>)
        .filter(([, values, allowed]) => allowed && values?.length)
        .map(([label, values]) => `${label}: ${values.join(', ')}`)
        .join(' | ');
}

function normalizeList(value: unknown): string[] {
    if (Array.isArray(value)) {
        return value.map(item => String(item).trim()).filter(Boolean);
    }

    if (typeof value === 'string') {
        return value
            .split(/[,\n]/)
            .map(item => item.trim())
            .filter(Boolean);
    }

    return [];
}

function getFindingStride(finding: ScanResult['findings'][number], frameworks?: string[]): string[] {
    const enabled = normalizeFrameworkCodes(frameworks);
    if (enabled.size > 0 && !enabled.has('STRIDE')) {
        return [];
    }

    return normalizeList(finding.stride);
}

function getFindingSignals(finding: ScanResult['findings'][number]): string[] {
    return normalizeList(finding.matchedSignals);
}

function getFindingLikelihood(finding: ScanResult['findings'][number]): string {
    return String(finding.likelihood ?? 'MEDIUM').toUpperCase();
}

function getFindingLikelihoodReasons(finding: ScanResult['findings'][number]): string[] {
    return normalizeList(finding.likelihoodReasons);
}

function getAiConfidence(finding: ScanResult['findings'][number]): number {
    return finding.aiReviewScores?.final ?? finding.resolverConfidence ?? finding.confidence ?? 0;
}

function isLowConfidenceAiFinding(finding: ScanResult['findings'][number]): boolean {
    return finding.provenance !== 'deterministic' && getAiConfidence(finding) < 0.75;
}

function needsManualReview(finding: ScanResult['findings'][number]): boolean {
    const corroboration = getCorroborationLabel(finding);
    return finding.provenance !== 'deterministic'
        && (isLowConfidenceAiFinding(finding) || corroboration === 'UNVERIFIED' || corroboration === 'PARTIAL');
}

function getCanonicalRemediation(finding: ScanResult['findings'][number]): {
    remediation: string;
    recommendedActions: string[];
    cheatSheetGuidance: string[];
    refs: string[];
    modelNote?: string;
    frameworkVariant?: { framework: string; summary: string; recommendedActions: string[] };
    validationSteps: string[];
    unsafeAlternatives: string[];
} {
    return resolveRemediationForFinding(finding);
}

function summarizeFileResult(result: ScanResult): string {
    if (!result.findings.length) {
        return (result.warnings ?? []).length
            ? 'No findings detected. Scan completed with provider/backend warnings.'
            : 'No findings detected.';
    }

    const highestSeverityFinding = [...result.findings]
        .sort((left, right) => riskRank(right) - riskRank(left))[0];

    const severityText = highestSeverityFinding.severity.toLowerCase();
    const likelihoodText = getFindingLikelihood(highestSeverityFinding).toLowerCase();
    const title = highestSeverityFinding.canonicalTitle || highestSeverityFinding.title || 'finding';
    const family = highestSeverityFinding.canonicalFamilyLabel || highestSeverityFinding.canonicalFamily;
    const additionalCount = result.findings.length - 1;

    return [
        `${result.findings.length === 1 ? 'One' : result.findings.length} ${result.findings.length === 1 ? 'finding was' : 'findings were'} identified, led by a ${severityText}-impact/${likelihoodText}-likelihood ${title} (${highestSeverityFinding.riskScore ?? 'n/a'}/10 risk).`,
        family ? `Primary issue family: ${family}.` : '',
        additionalCount > 0 ? `${additionalCount} additional finding(s) also detected.` : '',
    ].filter(Boolean).join(' ');
}

function hasPartialAiCoverage(result: ScanResult): boolean {
    return (result.warnings ?? []).some(warning =>
        /deterministic-only|AI coverage intentionally paused|AI provider unavailable|\b429\b|rate limit/i.test(warning),
    );
}

function hasProviderRateLimitWarning(warnings: Array<{ file: string; warning: string }>): boolean {
    return warnings.some(item => /\b429\b|rate limit|too many requests/i.test(item.warning));
}

function usesAiForFindings(result: ScanResult): boolean {
    return result.findings.some(finding => finding.provenance === 'ai');
}

function getAiUsageSummary(result: ScanResult): { requestCount: number; totalTokens: number } {
    return result.aiUsage ?? { requestCount: 0, totalTokens: 0 };
}

function summarizeFindingRow(finding: ScanResult['findings'][number]): string {
    const scanTier = getScanTierDisplayLabel(finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI'));
    const confidence = getConfidenceDisplayLabel(finding.confidenceTier ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'PLAUSIBLE'));
    const corroboration = getCorroborationDisplayLabel(finding.corroboration ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'UNVERIFIED'));
    const reviewFlag = needsManualReview(finding) ? ' | manual review recommended' : '';
    const parts = [
        `mode ${scanTier}`,
        `confidence ${confidence}`,
        `evidence ${corroboration}`,
    ];

    if (finding.provenance !== 'deterministic') {
        parts.push(formatAiPassScoreSummary(finding));
    }

    parts.push(
        `impact ${finding.severity.toLowerCase()}`,
        `likelihood ${getFindingLikelihood(finding).toLowerCase()}`,
        `risk ${finding.riskScore ?? 'n/a'}/10`,
    );

    return parts.join(' | ') + reviewFlag;
}

function formatPercent(value: number | undefined): string {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return 'n/a';
    }

    return `${Math.round(value * 100)}%`;
}

function formatAiPassScoreSummary(finding: ScanResult['findings'][number]): string {
    const scores = finding.aiReviewScores;
    return [
        `finder ${formatPercent(scores?.finder ?? finding.resolverConfidence ?? finding.confidence)}`,
        `verifier ${formatPercent(scores?.verifier)}`,
        `skeptic ${formatPercent(scores?.skeptic)}`,
        `final ${formatPercent(scores?.final ?? getAiConfidence(finding))}`,
    ].join(' | ');
}

function buildAiReviewTrailLines(finding: ScanResult['findings'][number]): string[] {
    if (finding.provenance !== 'ai') {
        return [];
    }

    const notes = finding.aiReviewNotes;
    const lines: string[] = [];

    if (notes?.finder) {
        lines.push(`- Finder said: ${notes.finder}`);
    }
    if (notes?.verifier) {
        lines.push(`- Verifier said: ${notes.verifier}`);
    }
    if (notes?.skeptic) {
        lines.push(`- Skeptic said: ${notes.skeptic}`);
    }

    return lines;
}

function getCorroborationLabel(finding: ScanResult['findings'][number]): string {
    return finding.corroboration ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'UNVERIFIED');
}

function summarizeCorroborationCounts(findings: ScanResult['findings']): string {
    const order: Array<'PROVEN' | 'CORROBORATED' | 'PARTIAL' | 'UNVERIFIED'> = ['PROVEN', 'CORROBORATED', 'PARTIAL', 'UNVERIFIED'];
    const counts = new Map<string, number>();

    for (const finding of findings) {
        const label = getCorroborationLabel(finding);
        counts.set(label, (counts.get(label) ?? 0) + 1);
    }

    return order
        .filter(label => (counts.get(label) ?? 0) > 0)
        .map(label => `${label.toLowerCase()}: ${counts.get(label)}`)
        .join(' | ');
}

function summarizeScanTierCounts(findings: ScanResult['findings']): string {
    const order: Array<'STATIC' | 'TARGETED_AI' | 'REPO_AI'> = ['STATIC', 'TARGETED_AI', 'REPO_AI'];
    const counts = new Map<string, number>();

    for (const finding of findings) {
        const label = finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI');
        counts.set(label, (counts.get(label) ?? 0) + 1);
    }

    return order
        .filter(label => (counts.get(label) ?? 0) > 0)
        .map(label => `${label.toLowerCase()}: ${counts.get(label)}`)
        .join(' | ');
}

function getPrimaryScanTierLabel(findings: ScanResult['findings']): string {
    const order: Array<'REPO_AI' | 'TARGETED_AI' | 'STATIC'> = ['REPO_AI', 'TARGETED_AI', 'STATIC'];
    for (const label of order) {
        if (findings.some(finding => (finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI')) === label)) {
            return label;
        }
    }

    return 'none';
}

function getScanTierDisplayLabel(value: string): string {
    switch (value) {
        case 'STATIC':
            return 'Static proof';
        case 'TARGETED_AI':
            return 'Targeted AI review';
        case 'REPO_AI':
            return 'Repo-context AI review';
        default:
            return value;
    }
}

function getConfidenceDisplayLabel(value: string): string {
    switch (value) {
        case 'PROVEN':
            return 'Confirmed by rule';
        case 'PLAUSIBLE':
            return 'AI-reviewed';
        default:
            return value;
    }
}

function getCorroborationDisplayLabel(value: string): string {
    switch (value) {
        case 'PROVEN':
            return 'Confirmed by rule';
        case 'CORROBORATED':
            return 'Validated by AI review';
        case 'PARTIAL':
            return 'Partially validated';
        case 'UNVERIFIED':
            return 'Needs manual review';
        default:
            return value;
    }
}

function buildHowToReadTable(): string[] {
    return [
        '## How To Read This Report',
        '',
        '| Report field | What it means | How to use it |',
        '| --- | --- | --- |',
        '| Confidence | How sure Owlvex is that the issue is real | Use this as the trust level for the finding |',
        '| Confirmed by rule | Deterministic analysis proved the issue from code structure | Highest confidence |',
        '| Validated by AI review | AI found the issue and a follow-up review supported it | Strong signal, but not rule-proven |',
        '| Partially validated | Some supporting evidence exists, but verification was incomplete | Review before acting |',
        '| Needs manual review | Evidence is weak, incomplete, or low-confidence | Do not treat as confirmed yet |',
        '| Impact | How serious the damage could be if exploited | Business/security severity |',
        '| Likelihood | How likely exploitation is from the observed code | Exploitability estimate |',
        '| Risk score | Overall priority if the finding is real | Use this to prioritize fixes |',
        '| Detection confidence | Confidence in the detection itself | Separate from risk score |',
        '',
    ];
}

function buildSafePatternLine(
    remediation: ReturnType<typeof getCanonicalRemediation>,
): string | undefined {
    if (remediation.frameworkVariant?.summary) {
        return remediation.frameworkVariant.summary;
    }

    if (remediation.modelNote) {
        return remediation.modelNote;
    }

    return undefined;
}

function buildRecommendedStepsLine(
    remediation: ReturnType<typeof getCanonicalRemediation>,
): string | undefined {
    if (remediation.recommendedActions.length) {
        return remediation.recommendedActions.join(' | ');
    }

    if (remediation.frameworkVariant?.recommendedActions.length) {
        return remediation.frameworkVariant.recommendedActions.join(' | ');
    }

    return undefined;
}

function buildAttackSurfaceAssessment(
    totalFindings: number,
    deterministicCount: number,
    metrics: { critical: number; high: number; medium: number; low: number },
    topFamilies: string[],
    filesScanned: number,
    filesWithFindings: number,
): string[] {
    const out: string[] = ['## Attack Surface Assessment', ''];

    if (totalFindings === 0) {
        out.push(
            'No vulnerabilities were identified in this scan. ' +
            'This does not guarantee the codebase is free of security issues - ' +
            'the scan covers the patterns and frameworks active during this run.',
        );
        out.push('');
        return out;
    }

    const criticalHigh = metrics.critical + metrics.high;
    const urgencyPhrase = metrics.critical > 0
        ? `including **${metrics.critical} critical-severity** exposure${metrics.critical > 1 ? 's' : ''} requiring immediate remediation`
        : criticalHigh > 0
        ? `**${criticalHigh} requiring immediate attention**`
        : 'all classified medium or lower severity';

    out.push(
        `Owlvex identified **${totalFindings} security ${totalFindings === 1 ? 'vulnerability' : 'vulnerabilities'}** ` +
        `across ${filesWithFindings} of ${filesScanned} scanned ${filesScanned === 1 ? 'file' : 'files'}, ` +
        `${urgencyPhrase}.`,
    );
    out.push('');

    if (deterministicCount > 0) {
        out.push(
            `**${deterministicCount} ${deterministicCount === 1 ? 'finding was' : 'findings were'} confirmed ` +
            `by deterministic structural analysis** - these are invariant violations in the code structure, ` +
            `not probabilistic inferences. Each carries 100% confidence and requires no additional validation ` +
            `before escalation.`,
        );
        out.push('');
    }

    if (topFamilies.length > 0) {
        const last = topFamilies[topFamilies.length - 1];
        const familyText = topFamilies.length === 1
            ? topFamilies[0]
            : `${topFamilies.slice(0, -1).join(', ')} and ${last}`;
        out.push(`The dominant exposure categories are **${familyText}**.`);
        out.push('');
    }

    return out;
}

function buildDeterministicPanel(
    items: Array<{ file: string; finding: ScanResult['findings'][number] }>,
): string[] {
    if (items.length === 0) { return []; }

    const sorted = [...items].sort(
        (a, b) => severityRank(b.finding.severity) - severityRank(a.finding.severity),
    );

    const out: string[] = [
        '## Deterministic Detections',
        '',
        'These findings were produced by rule-based structural analysis. ' +
        'Each represents a confirmed code-level invariant violation - not a heuristic match.',
        '',
        '| Rule | Issue | File | Line | Severity |',
        '| :--- | :--- | :--- | ---: | :--- |',
    ];

    for (const item of sorted) {
        const rule = item.finding.ruleCode || '-';
        const title = escapeMarkdown(item.finding.canonicalTitle || item.finding.title);
        out.push(
            `| Deterministic \`${rule}\` | ${title} | \`${item.file}\` | ${item.finding.line} | **${item.finding.severity}** |`,
        );
    }

    out.push('');
    return out;
}

function buildOverallPriorityLine(
    findingsByFile: Array<{ file: string; result: ScanResult; packContext?: ScanResult['packContext'] }>,
): string {
    const firstRiskyFile = findingsByFile.find(item => item.result.findings.length > 0);
    if (!firstRiskyFile) {
        return 'Start with: no active findings were identified in this scan.';
    }

    const topFinding = [...firstRiskyFile.result.findings]
        .sort((left, right) => riskRank(right) - riskRank(left))[0];
    const title = topFinding.canonicalTitle || topFinding.title || 'Top finding';
    return `Start with: ${title} in \`${firstRiskyFile.file}\` (${topFinding.riskScore ?? 'n/a'}/10 risk).`;
}

function buildScanTrustLine(results: ReportSnapshot['results']): string {
    const findings = results.flatMap(item => item.result.findings);
    if (!findings.length) {
        return 'This scan did not produce active findings. Coverage and provider status are listed below.';
    }

    const deterministicCount = findings.filter(finding => finding.provenance === 'deterministic').length;
    const repoAiCount = findings.filter(finding => (finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI')) === 'REPO_AI').length;
    const targetedCount = findings.filter(finding => (finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI')) === 'TARGETED_AI').length;

    const parts: string[] = [];
    if (deterministicCount > 0) {
        parts.push(`${deterministicCount} proven by static rules`);
    }
    if (targetedCount > 0) {
        parts.push(`${targetedCount} reviewed with targeted AI`);
    }
    if (repoAiCount > 0) {
        parts.push(`${repoAiCount} strengthened with repo context`);
    }

    return `This scan established: ${parts.join('; ')}.`;
}

function buildKnowledgeSourcesSummary(results: ReportSnapshot['results']): string {
    const packModes = new Map<string, number>();
    for (const item of results) {
        const label = getRulePackModeLabel(item.result.packContext);
        packModes.set(label, (packModes.get(label) ?? 0) + 1);
    }

    return [...packModes.entries()]
        .map(([label, count]) => {
            if (/^Bundled Fallback$/i.test(label)) {
                return `Bundled fallback rules only (${count})`;
            }
            if (/^Fresh Packs$/i.test(label)) {
                return `Fresh packs (${count})`;
            }
            return `${label} (${count})`;
        })
        .join(' | ') || 'Bundled fallback rules only (0)';
}

function buildKnowledgeSourceDetail(packContext?: ScanResult['packContext']): string {
    const label = getRulePackModeLabel(packContext);
    if (/^Bundled Fallback$/i.test(label)) {
        return 'Bundled fallback rules only';
    }

    return describeRulePackRuntime(packContext);
}

function buildProjectContextLabel(summary: string): string {
    if (!summary || summary === 'none') {
        return 'none';
    }

    if (summary.startsWith('file ')) {
        return `loaded from ${summary.slice(5)}`;
    }

    return summary;
}

function buildConfidencePostureLine(
    findings: ScanResult['findings'],
): string {
    if (!findings.length) {
        return 'No findings to validate.';
    }

    const proven = findings.filter(finding => getCorroborationLabel(finding) === 'PROVEN').length;
    const corroborated = findings.filter(finding => getCorroborationLabel(finding) === 'CORROBORATED').length;
    const manualReview = findings.filter(finding => needsManualReview(finding)).length;
    const partial = findings.filter(finding => getCorroborationLabel(finding) === 'PARTIAL').length;

    const parts: string[] = [];
    if (proven > 0) {
        parts.push(`${proven} verified`);
    }
    if (corroborated > 0) {
        parts.push(`${corroborated} cross-checked`);
    }
    if (partial > 0) {
        parts.push(`${partial} partially validated`);
    }
    if (manualReview > 0) {
        parts.push(`${manualReview} need manual review`);
    }

    return parts.join(' | ') || 'No findings to validate.';
}

function buildFixFirstLines(
    findingsByFile: Array<{ file: string; result: ScanResult }>,
): string[] {
    const risky = findingsByFile.filter(item => item.result.findings.length > 0).slice(0, 3);
    if (!risky.length) {
        return ['No immediate action needed from this scan.', ''];
    }

    const lines: string[] = [];
    for (const item of risky) {
        const topFinding = [...item.result.findings].sort((left, right) => riskRank(right) - riskRank(left))[0];
        const title = topFinding.canonicalTitle || topFinding.title;
        const confidenceSuffix = needsManualReview(topFinding) ? ' Manual review recommended before acting.' : '';
        const remediation = getCanonicalRemediation(topFinding).remediation;
        lines.push(`- \`${item.file}\` (${item.result.score.toFixed(1)}/10): ${title}. ${remediation}${confidenceSuffix}`);
    }
    lines.push('');
    return lines;
}

function getFindingStatusLabel(finding: ScanResult['findings'][number]): string {
    if (finding.provenance === 'deterministic') return 'Confirmed by static rule';
    if (needsManualReview(finding)) return 'Needs manual review';
    if (finding.corroboration === 'CORROBORATED') return 'AI-reviewed';
    if (finding.corroboration === 'PARTIAL') return 'Partially validated';
    return 'AI candidate';
}

async function buildSummaryFindingLines(
    root: vscode.Uri,
    items: Array<{ file: string; finding: ScanResult['findings'][number]; result: ScanResult }>,
): Promise<string[]> {
    if (!items.length) {
        return [
            'No active findings were returned by this scan.',
            '',
        ];
    }

    const lines: string[] = [];
    for (const item of items.slice(0, 5)) {
        const remediation = getCanonicalRemediation(item.finding);
        const snippet = await readCodeSnippet(root, item.file, item.finding.line, item.finding.lineEnd);
        lines.push(`### ${item.finding.canonicalTitle || item.finding.title}`);
        lines.push('');
        lines.push(`- File: \`${item.file}\` at L${item.finding.line}${item.finding.lineEnd !== item.finding.line ? `-${item.finding.lineEnd}` : ''}`);
        lines.push(`- Status: ${getFindingStatusLabel(item.finding)}`);
        lines.push(`- Risk: ${item.finding.severity} impact / ${getFindingLikelihood(item.finding)} likelihood / ${item.finding.riskScore ?? 'n/a'}/10`);
        lines.push(`- Why it matters: ${item.finding.explanation || 'No explanation returned.'}`);
        lines.push(`- What to change: ${remediation.remediation}`);
        if (needsManualReview(item.finding)) {
            lines.push('- Review before acting: this AI finding is not fully corroborated.');
        }
        if (snippet) {
            lines.push('- Code involved:');
            lines.push('```text');
            lines.push(escapeCodeFence(snippet));
            lines.push('```');
        }
        lines.push('');
    }
    return lines;
}

export async function generateWorkspaceScanReport(root: vscode.Uri, summary: FolderScanSummary): Promise<vscode.Uri> {
    return generateReportFromSnapshot(root, {
        targetLabel: root.fsPath,
        outputRoot: root,
        errors: summary.errors,
        results: summary.results,
    });
}

export async function generateReportFromSnapshot(root: vscode.Uri, snapshot: ReportSnapshot, options: ReportGenerationOptions = {}): Promise<vscode.Uri> {
    const now = new Date();
    const variant = options.variant ?? 'full';
    const reportFileName = variant === 'summary'
        ? `owlvex-summary-report-${formatTimestamp(now)}.md`
        : `owlvex-scan-report-${formatTimestamp(now)}.md`;
    const reportUri = vscode.Uri.joinPath(root, reportFileName);
    const warnings = snapshot.results.flatMap(item =>
        (item.result.warnings ?? []).map(warning => ({
            file: formatReportPath(root.fsPath, item.uri.fsPath),
            warning,
        })),
    );
    const packCoverageSummary = buildKnowledgeSourcesSummary(snapshot.results);
    const projectContextSummary = [...new Set(
        snapshot.results
            .map(item => item.result.projectContextSummary)
            .filter((value): value is string => Boolean(value && value !== 'none')),
    )].join(' | ') || 'none';

    const aggregateMetrics = snapshot.results.reduce(
        (totals, item) => ({
            critical: totals.critical + item.result.metrics.critical,
            high: totals.high + item.result.metrics.high,
            medium: totals.medium + item.result.metrics.medium,
            low: totals.low + item.result.metrics.low,
        }),
        { critical: 0, high: 0, medium: 0, low: 0 },
    );

    const riskyFiles = [...snapshot.results]
        .sort((a, b) => {
            if (a.result.score !== b.result.score) return b.result.score - a.result.score;
            return b.result.findings.length - a.result.findings.length;
        })
        .slice(0, 10);

    const findingsByFramework = snapshot.results
        .flatMap(item => item.result.findings.map(finding => ({
            file: formatReportPath(root.fsPath, item.uri.fsPath),
            finding,
            packContext: item.result.packContext,
        })))
        .reduce((acc, item) => {
            const key = item.finding.framework || 'Unspecified';
            acc.set(key, [...(acc.get(key) ?? []), item]);
            return acc;
        }, new Map<string, Array<{ file: string; finding: ScanResult['findings'][number]; packContext?: ScanResult['packContext'] }>>());

    const findingsByFamily = snapshot.results
        .flatMap(item => item.result.findings.map(finding => ({
            file: formatReportPath(root.fsPath, item.uri.fsPath),
            finding,
            packContext: item.result.packContext,
        })))
        .reduce((acc, item) => {
            const key = item.finding.canonicalFamilyLabel || item.finding.canonicalFamily || 'Unclassified';
            acc.set(key, [...(acc.get(key) ?? []), item]);
            return acc;
        }, new Map<string, Array<{ file: string; finding: ScanResult['findings'][number]; packContext?: ScanResult['packContext'] }>>());

    const findingsByCanonicalIssue = snapshot.results
        .flatMap(item => item.result.findings.map(finding => ({
            file: formatReportPath(root.fsPath, item.uri.fsPath),
            finding,
            packContext: item.result.packContext,
        })))
        .reduce((acc, item) => {
            const key = item.finding.canonicalId || item.finding.ruleCode || item.finding.title || 'Unresolved';
            acc.set(key, [...(acc.get(key) ?? []), item]);
            return acc;
        }, new Map<string, Array<{ file: string; finding: ScanResult['findings'][number]; packContext?: ScanResult['packContext'] }>>());

    const findingsByFile = snapshot.results
        .map(item => ({
            file: formatReportPath(root.fsPath, item.uri.fsPath),
            result: item.result,
            packContext: item.result.packContext,
        }))
        .sort((a, b) => {
            if (a.result.score !== b.result.score) return b.result.score - a.result.score;
            return b.result.findings.length - a.result.findings.length;
        });

    const allFindingItems = snapshot.results.flatMap(item =>
        item.result.findings.map(finding => ({
            file: formatReportPath(root.fsPath, item.uri.fsPath),
            finding,
            packContext: item.result.packContext,
        })),
    );
    const deterministicItems = allFindingItems.filter(item => item.finding.provenance === 'deterministic');
    const topFamilies = [...findingsByFamily.entries()]
        .sort((a, b) => b[1].length - a[1].length)
        .slice(0, 3)
        .map(([label]) => label)
        .filter(label => label !== 'Unclassified');

    const totalFindings = snapshot.results.reduce(
        (total, item) => total + item.result.findings.length,
        0,
    );
    const highestFileRisk = findingsByFile.length
        ? Math.max(...findingsByFile.map(item => item.result.score))
        : 0;
    const cleanFiles = snapshot.results.filter(item => item.result.findings.length === 0).length;
    const manualReviewAiCount = allFindingItems.filter(item => needsManualReview(item.finding)).length;
    const allFindings = snapshot.results.flatMap(item => item.result.findings);
    const aggregateAiUsage = snapshot.results.reduce((total, item) => {
        const usage = getAiUsageSummary(item.result);
        return {
            requestCount: total.requestCount + usage.requestCount,
            totalTokens: total.totalTokens + usage.totalTokens,
        };
    }, { requestCount: 0, totalTokens: 0 });

    if (variant === 'summary') {
        const sortedFindingItems = snapshot.results
            .flatMap(item => item.result.findings.map(finding => ({
                file: formatReportPath(root.fsPath, item.uri.fsPath),
                finding,
                result: item.result,
            })))
            .sort((left, right) => {
                const leftManual = needsManualReview(left.finding) ? 1 : 0;
                const rightManual = needsManualReview(right.finding) ? 1 : 0;
                if (leftManual !== rightManual) return leftManual - rightManual;
                return riskRank(right.finding) - riskRank(left.finding);
            });
        const confirmedItems = sortedFindingItems.filter(item => !needsManualReview(item.finding));
        const manualReviewItems = sortedFindingItems.filter(item => needsManualReview(item.finding));
        const lines: string[] = [
            '# Owlvex Summary Report',
            '',
            `Generated: ${now.toISOString()}`,
            `Target: \`${snapshot.targetLabel}\``,
            `Report location: \`${root.fsPath}\``,
            '',
            'This is the developer summary view. Use the full evidence report for complete scoring, framework mappings, AI review detail, and audit context.',
            '',
            '## What To Fix First',
            '',
            `- ${buildOverallPriorityLine(findingsByFile)}`,
            `- ${buildScanTrustLine(snapshot.results)}`,
            `- Confidence posture: ${buildConfidencePostureLine(allFindings)}`,
            `- Files scanned: ${snapshot.results.length}`,
            `- Total findings: ${totalFindings}`,
            `- Manual-review findings: ${manualReviewAiCount}`,
            '',
            '## Confirmed Or AI-Reviewed Findings',
            '',
            ...(await buildSummaryFindingLines(root, confirmedItems.length ? confirmedItems : sortedFindingItems)),
        ];

        if (manualReviewItems.length) {
            lines.push('## Needs Manual Review');
            lines.push('');
            lines.push('These findings may still be useful, but they were not fully corroborated by the scan.');
            lines.push('');
            lines.push(...(await buildSummaryFindingLines(root, manualReviewItems)));
        }

        if (warnings.length || snapshot.errors.length || hasProviderRateLimitWarning(warnings)) {
            lines.push('## Scan Notes');
            lines.push('');
            lines.push(`- Coverage: ${snapshot.results.some(item => hasPartialAiCoverage(item.result)) ? 'Partial AI coverage in this scan' : 'Normal for the current provider and runtime state'}`);
            lines.push(`- Errors: ${snapshot.errors.length}`);
            lines.push(`- Scan warnings: ${warnings.length}`);
            if (hasProviderRateLimitWarning(warnings)) {
                lines.push(`- Provider rate limit note: this scan saw a 429/rate-limit signal. If it repeats, configure \`${PROFILE.configSection}.providerThrottleOverrides\` for the affected provider.`);
            }
            lines.push('');
        }

        await vscode.workspace.fs.writeFile(reportUri, Buffer.from(lines.join('\n'), 'utf8'));
        return reportUri;
    }

    const lines: string[] = [
        '# Owlvex Vulnerability Scan Report',
        '',
        `Generated: ${now.toISOString()}`,
        `Target: \`${snapshot.targetLabel}\``,
        `Report location: \`${root.fsPath}\``,
        '',
        '## Summary',
        '',
        `- ${buildOverallPriorityLine(findingsByFile)}`,
        `- ${buildScanTrustLine(snapshot.results)}`,
        `- Highest file risk: ${highestFileRisk.toFixed(1)}/10`,
        `- Clean files: ${cleanFiles}/${snapshot.results.length}`,
        `- Confidence posture: ${buildConfidencePostureLine(allFindings)}`,
        '',
        '## Fix First',
        '',
        ...buildFixFirstLines(findingsByFile),
        ...buildHowToReadTable(),
        '## Scan Facts',
        '',
        `- Files scanned: ${snapshot.results.length}`,
        `- Files with findings: ${snapshot.results.filter(item => item.result.findings.length > 0).length}`,
        `- Total findings: ${totalFindings}`,
        `- Static findings: ${deterministicItems.length}`,
        `- AI findings needing manual review: ${manualReviewAiCount}`,
        `- Confidence posture: ${buildConfidencePostureLine(allFindings)}`,
        '',
        '## AI Usage',
        '',
        `- Provider/model mix: ${[...new Set(snapshot.results.map(item => `${item.result.provider} / ${item.result.model}`))].join(' | ') || 'n/a'}`,
        `- AI requests: ${aggregateAiUsage.requestCount}`,
        `- Total AI tokens: ${aggregateAiUsage.totalTokens}`,
        `- Estimated cost: not yet available`,
        ...(hasProviderRateLimitWarning(warnings)
            ? [`- Provider rate limit note: this scan saw a 429/rate-limit signal. If it repeats, configure \`${PROFILE.configSection}.providerThrottleOverrides\` for the affected provider.`]
            : []),
        '',
        '## Coverage And Context',
        '',
        `- Coverage: ${snapshot.results.some(item => hasPartialAiCoverage(item.result)) ? 'Partial AI coverage in this scan' : 'Normal for the current provider and runtime state'}`,
        `- Knowledge sources: ${packCoverageSummary}`,
        `- Frameworks in scope: ${formatFrameworkSummary([...new Set(snapshot.results.flatMap(item => item.result.frameworks ?? []))])}`,
        `- Project context: ${buildProjectContextLabel(projectContextSummary)}`,
        `- Errors: ${snapshot.errors.length}`,
        `- Scan warnings: ${warnings.length}`,
        '',
    ];

    lines.push('## Findings By File', '');

    if (findingsByFile.length) {
        for (const item of findingsByFile) {
            lines.push(`### ${item.file}`);
            lines.push('');
            lines.push(`- File risk score: ${item.result.score.toFixed(1)}/10`);
            lines.push(`- Findings: ${item.result.findings.length}`);
            const fileAiUsage = getAiUsageSummary(item.result);
            lines.push(`- AI usage: ${fileAiUsage.requestCount} request(s), ${fileAiUsage.totalTokens} token(s)`);
            if (item.result.findings.length) {
                const topFinding = [...item.result.findings].sort((left, right) => riskRank(right) - riskRank(left))[0];
                lines.push(`- Fix first: ${topFinding.canonicalTitle || topFinding.title} (${topFinding.riskScore ?? 'n/a'}/10 risk)`);
                lines.push(`- Why this matters: ${topFinding.explanation || 'No explanation returned.'}`);
                lines.push(`- What to change: ${getCanonicalRemediation(topFinding).remediation}`);
            }
            lines.push(`- Confidence: ${buildConfidencePostureLine(item.result.findings)}`);
            lines.push(`- Manual review: ${item.result.findings.filter(finding => needsManualReview(finding)).length} AI finding(s) needing review`);
            lines.push('');

            if (!item.result.findings.length) {
                lines.push(`- Summary: ${summarizeFileResult(item.result)}`);
                lines.push(`- Coverage: ${hasPartialAiCoverage(item.result) ? 'Partial AI coverage or deterministic-only fallback affected this file' : 'Normal for this file'}`);
                lines.push(`- Project context: ${buildProjectContextLabel(item.result.projectContextSummary && item.result.projectContextSummary !== 'none' ? item.result.projectContextSummary : 'none')}`);
                lines.push('');
                continue;
            }

            lines.push('#### Technical Details');
            lines.push('');
            lines.push(`- Summary: ${summarizeFileResult(item.result)}`);
            lines.push(`- Coverage: ${hasPartialAiCoverage(item.result) ? 'Partial AI coverage or deterministic-only fallback affected this file' : 'Normal for this file'}`);
            lines.push(`- Analysis mode: ${item.result.findings.length ? getScanTierDisplayLabel(getPrimaryScanTierLabel(item.result.findings)) : 'none'}`);
            lines.push(`- Analysis mix: ${item.result.findings.length ? summarizeScanTierCounts(item.result.findings) : 'No findings to classify'}`);
            lines.push(`- Evidence: ${summarizeCorroborationCounts(item.result.findings)}`);
            if (!usesAiForFindings(item.result)) {
                lines.push('- AI review: not used for the final finding set in this file');
            }
            lines.push(`- Project context: ${buildProjectContextLabel(item.result.projectContextSummary && item.result.projectContextSummary !== 'none' ? item.result.projectContextSummary : 'none')}`);
            lines.push(`- Knowledge sources: ${buildKnowledgeSourceDetail(item.packContext)}`);
            lines.push('');
            lines.push('| Finding | What drives the score | Detection confidence |');
            lines.push('| --- | --- | --- |');
            for (const finding of item.result.findings.slice().sort((left, right) => riskRank(right) - riskRank(left))) {
                lines.push(
                    `| ${escapeMarkdown(finding.canonicalTitle || finding.title)} | ${escapeMarkdown(summarizeFindingRow(finding))} | ${finding.provenance === 'deterministic' ? `Confirmed by rule \`${finding.ruleCode || 'n/a'}\`` : `${Math.round((finding.resolverConfidence ?? finding.confidence) * 100)}%`} |`,
                );
            }
            lines.push('');

            for (const finding of item.result.findings.slice().sort((left, right) => riskRank(right) - riskRank(left))) {
                const snippet = await readCodeSnippet(root, item.file, finding.line, finding.lineEnd);
                const remediation = getCanonicalRemediation(finding);
                const safePattern = buildSafePatternLine(remediation);
                const likelihoodReasons = getFindingLikelihoodReasons(finding);
                const mappingSummary = formatMappings(finding.mappings, item.result.frameworks);
                const stride = getFindingStride(finding, item.result.frameworks);
                const signals = getFindingSignals(finding);
                lines.push(`#### ${finding.canonicalTitle || finding.title}`);
                lines.push(`- Location: \`${item.file}\` at L${finding.line}${finding.lineEnd !== finding.line ? `-${finding.lineEnd}` : ''}`);
                lines.push(`- Finding risk: ${finding.severity} impact / ${getFindingLikelihood(finding)} likelihood / ${finding.riskScore ?? 'n/a'}/10`);
                lines.push(`- Analysis mode: ${getScanTierDisplayLabel(finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI'))}`);
                lines.push(`- Confidence: ${getConfidenceDisplayLabel(finding.confidenceTier ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'PLAUSIBLE'))}`);
                if (finding.provenance !== 'deterministic') {
                    lines.push(`- AI pass scores: ${formatAiPassScoreSummary(finding)}`);
                    lines.push(`- Detection confidence: ${formatPercent(getAiConfidence(finding))}${needsManualReview(finding) ? ' (manual review recommended)' : ''}`);
                }
                lines.push(`- Evidence: ${getCorroborationDisplayLabel(finding.corroboration ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'UNVERIFIED'))}`);
                lines.push(...buildAiReviewTrailLines(finding));
                if (needsManualReview(finding)) {
                    lines.push('- Review note: This AI finding is not fully corroborated or has low confidence. Verify the classification, title, and remediation against the code before acting on it.');
                }
                lines.push(`- Why it matters: ${finding.explanation || 'No explanation returned.'}`);
                lines.push(`- What to change: ${remediation.remediation}`);
                if (safePattern) {
                    lines.push(`- Safe pattern: ${safePattern}`);
                }
                const recommendedSteps = buildRecommendedStepsLine(remediation);
                if (recommendedSteps) {
                    lines.push(`- Suggested steps: ${recommendedSteps}`);
                }
                if (remediation.validationSteps.length) {
                    lines.push(`- Validate with: ${remediation.validationSteps.join(' | ')}`);
                }
                if (remediation.unsafeAlternatives.length) {
                    lines.push(`- Avoid: ${remediation.unsafeAlternatives.join(' | ')}`);
                }
                if (remediation.cheatSheetGuidance.length) {
                    lines.push(`- Canonical grounding: ${remediation.cheatSheetGuidance.join(' || ')}`);
                }
                if (likelihoodReasons.length) {
                    lines.push(`- Why likely: ${likelihoodReasons.join(' | ')}`);
                }
                if (finding.threat) {
                    lines.push(`- Threat: ${finding.threat}`);
                }
                if (mappingSummary) {
                    lines.push(`- Mappings: ${mappingSummary}`);
                }
                if (stride.length) {
                    lines.push(`- STRIDE: ${stride.join(', ')}`);
                }
                if (signals.length) {
                    lines.push(`- Matched signals: ${signals.join(', ')}`);
                }
                if (remediation.refs.length) {
                    lines.push(`- Sources: ${remediation.refs.join(', ')}`);
                }
                if (finding.provenance === 'ai') {
                    const aiGroundingSources = [
                        'Curated framework pack',
                        ...(finding.canonicalId ? getGroundedCheatSheetLabelsForIssueIds([finding.canonicalId]).slice(0, 2) : []),
                    ];
                    if (aiGroundingSources.length) {
                        lines.push(`- AI grounding: ${aiGroundingSources.join(' | ')}`);
                    }
                }
                if (snippet) {
                    lines.push('- Code involved in the reasoning:');
                    lines.push('```text');
                    lines.push(escapeCodeFence(snippet));
                    lines.push('```');
                }
                lines.push('');
            }
        }
    } else {
        lines.push('No detailed findings were returned.');
        lines.push('');
    }

    if (snapshot.errors.length) {
        lines.push('## Scan Errors');
        lines.push('');
        for (const error of snapshot.errors) {
            lines.push(`- ${error}`);
        }
        lines.push('');
    }

    if (warnings.length) {
        lines.push('## Scan Warnings');
        lines.push('');
        for (const warning of warnings) {
            lines.push(`- ${warning.file}: ${warning.warning}`);
        }
        lines.push('');
    }

    await vscode.workspace.fs.writeFile(reportUri, Buffer.from(lines.join('\n'), 'utf8'));
    return reportUri;
}

async function readCodeSnippet(root: vscode.Uri, relativeFile: string, line: number, lineEnd: number): Promise<string> {
    try {
        const fileUri = vscode.Uri.joinPath(root, relativeFile);
        const raw = await vscode.workspace.fs.readFile(fileUri);
        const content = Buffer.from(raw).toString('utf8');
        const allLines = content.split(/\r?\n/);
        const start = Math.max(0, line - 2);
        const end = Math.min(allLines.length, Math.max(lineEnd, line) + 1);
        return allLines
            .slice(start, end)
            .map((text, index) => `${String(start + index + 1).padStart(4, ' ')} | ${text}`)
            .join('\n');
    } catch {
        return '';
    }
}

function severityRank(severity: string): number {
    switch (severity) {
        case 'CRITICAL':
            return 4;
        case 'HIGH':
            return 3;
        case 'MEDIUM':
            return 2;
        case 'LOW':
            return 1;
        default:
            return 0;
    }
}

function riskRank(finding: ScanResult['findings'][number]): number {
    return (finding.riskScore ?? 0) * 10 + severityRank(finding.severity);
}
