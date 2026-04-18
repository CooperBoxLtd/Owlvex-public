import * as path from 'path';
import * as vscode from 'vscode';
import { getGroundedCheatSheetLabelsForIssueIds, resolveRemediationForFinding } from '../frameworks/remediationResolver';
import { describeRulePackRuntime, getRulePackModeLabel } from '../packs/packRuntime';
import { ScanResult } from './scanEngine';
import { FolderScanSummary } from './workspaceScanner';
import { formatFrameworkSummary } from '../frameworks/catalog';

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

function getCanonicalRemediation(finding: ScanResult['findings'][number]): {
    remediation: string;
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
        `${result.findings.length} finding(s), led by a ${severityText}-impact/${likelihoodText}-likelihood ${title} (${highestSeverityFinding.riskScore ?? 'n/a'}/10 risk).`,
        family ? `Primary issue family: ${family}.` : '',
        additionalCount > 0 ? `${additionalCount} additional finding(s) also detected.` : '',
    ].filter(Boolean).join(' ');
}

function hasPartialAiCoverage(result: ScanResult): boolean {
    return (result.warnings ?? []).some(warning =>
        /deterministic-only|AI coverage intentionally paused|AI provider unavailable|\b429\b|rate limit/i.test(warning),
    );
}

function summarizeFindingRow(finding: ScanResult['findings'][number]): string {
    const scanTier = getScanTierDisplayLabel(finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI'));
    const confidence = getConfidenceDisplayLabel(finding.confidenceTier ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'PLAUSIBLE'));
    const corroboration = getCorroborationDisplayLabel(finding.corroboration ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'UNVERIFIED'));
    return [
        `mode ${scanTier}`,
        `confidence ${confidence}`,
        `evidence ${corroboration}`,
        `impact ${finding.severity.toLowerCase()}`,
        `likelihood ${getFindingLikelihood(finding).toLowerCase()}`,
        `risk ${finding.riskScore ?? 'n/a'}/10`,
    ].join(' | ');
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
            return 'Proven';
        case 'PLAUSIBLE':
            return 'Plausible';
        default:
            return value;
    }
}

function getCorroborationDisplayLabel(value: string): string {
    switch (value) {
        case 'PROVEN':
            return 'Proven';
        case 'CORROBORATED':
            return 'Cross-checked';
        case 'PARTIAL':
            return 'Needs confirmation';
        case 'UNVERIFIED':
            return 'Not confirmed yet';
        default:
            return value;
    }
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

export async function generateWorkspaceScanReport(root: vscode.Uri, summary: FolderScanSummary): Promise<vscode.Uri> {
    return generateReportFromSnapshot(root, {
        targetLabel: root.fsPath,
        outputRoot: root,
        errors: summary.errors,
        results: summary.results,
    });
}

export async function generateReportFromSnapshot(root: vscode.Uri, snapshot: ReportSnapshot): Promise<vscode.Uri> {
    const now = new Date();
    const reportFileName = `owlvex-scan-report-${formatTimestamp(now)}.md`;
    const reportUri = vscode.Uri.joinPath(root, reportFileName);
    const scores = snapshot.results.map(item => item.result.score);
    const averageScore = scores.length
        ? scores.reduce((total, score) => total + score, 0) / scores.length
        : 0;
    const warnings = snapshot.results.flatMap(item =>
        (item.result.warnings ?? []).map(warning => ({
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
            warning,
        })),
    );
    const packModes = new Map<string, number>();
    for (const item of snapshot.results) {
        const label = getRulePackModeLabel(item.result.packContext);
        packModes.set(label, (packModes.get(label) ?? 0) + 1);
    }
    const packCoverageSummary = [...packModes.entries()]
        .map(([label, count]) => `${label}: ${count}`)
        .join(' | ') || 'Bundled Fallback: 0';
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
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
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
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
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
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
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
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
            result: item.result,
            packContext: item.result.packContext,
        }))
        .sort((a, b) => {
            if (a.result.score !== b.result.score) return b.result.score - a.result.score;
            return b.result.findings.length - a.result.findings.length;
        });

    const allFindingItems = snapshot.results.flatMap(item =>
        item.result.findings.map(finding => ({
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
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

    const lines: string[] = [
        '# Owlvex Vulnerability Scan Report',
        '',
        `Generated: ${now.toISOString()}`,
        `Target: \`${snapshot.targetLabel}\``,
        `Report location: \`${root.fsPath}\``,
        '',
        '## Summary',
        '',
        `- Files scanned: ${snapshot.results.length}`,
        `- Files with findings: ${snapshot.results.filter(item => item.result.findings.length > 0).length}`,
        `- Total findings: ${totalFindings}`,
        `- Average file risk score: ${averageScore.toFixed(1)}/10`,
        `- Deterministic findings: ${deterministicItems.length}`,
        `- Intelligence source coverage: ${packCoverageSummary}`,
        `- Frameworks in scope: ${formatFrameworkSummary([...new Set(snapshot.results.flatMap(item => item.result.frameworks ?? []))])}`,
        `- Errors: ${snapshot.errors.length}`,
        `- Scan warnings: ${warnings.length}`,
        `- Coverage posture: ${snapshot.results.some(item => hasPartialAiCoverage(item.result)) ? 'Partial AI coverage in this scan' : 'Full scan posture for current provider/runtime state'}`,
        `- Analysis mode: ${totalFindings > 0 ? getScanTierDisplayLabel(getPrimaryScanTierLabel(snapshot.results.flatMap(item => item.result.findings))) : 'none'}`,
        `- Analysis mix: ${totalFindings > 0 ? summarizeScanTierCounts(snapshot.results.flatMap(item => item.result.findings)) : 'No findings to classify'}`,
        `- Evidence: ${totalFindings > 0 ? summarizeCorroborationCounts(snapshot.results.flatMap(item => item.result.findings)) : 'No findings to corroborate'}`,
        `- Project context: ${projectContextSummary}`,
        '- Score guide: file risk score equals the highest remaining finding risk in that file; finding risk is the 0-10 risk of a specific issue.',
        '',
    ];

    lines.push('## Findings By File', '');

    if (findingsByFile.some(item => item.result.findings.length)) {
        for (const item of findingsByFile.filter(entry => entry.result.findings.length)) {
            lines.push(`### ${item.file}`);
            lines.push('');
            lines.push(`- File risk score: ${item.result.score.toFixed(1)}/10`);
            lines.push(`- Findings: ${item.result.findings.length}`);
            lines.push(`- Frameworks in scope: ${formatFrameworkSummary(item.result.frameworks ?? [])}`);
            lines.push(`- Summary: ${summarizeFileResult(item.result)}`);
            lines.push(`- Coverage posture: ${hasPartialAiCoverage(item.result) ? 'Partial AI coverage or deterministic-only fallback affected this file' : 'Normal coverage for this file'}`);
            lines.push(`- Analysis mode: ${item.result.findings.length ? getScanTierDisplayLabel(getPrimaryScanTierLabel(item.result.findings)) : 'none'}`);
            lines.push(`- Analysis mix: ${item.result.findings.length ? summarizeScanTierCounts(item.result.findings) : 'No findings to classify'}`);
            lines.push(`- Evidence: ${summarizeCorroborationCounts(item.result.findings)}`);
            lines.push(`- Project context: ${item.result.projectContextSummary && item.result.projectContextSummary !== 'none' ? item.result.projectContextSummary : 'none'}`);
            lines.push('- Score guide: fix the highest finding risk first; the file risk score then drops to the next-highest remaining finding, and reaches 0 when no findings remain.');
            lines.push(`- Intelligence source: ${describeRulePackRuntime(item.packContext)}`);
            lines.push('');
            lines.push('| Finding | Score Factors | Detection |');
            lines.push('| --- | --- | --- |');
            for (const finding of item.result.findings.slice().sort((left, right) => riskRank(right) - riskRank(left))) {
                lines.push(
                    `| ${escapeMarkdown(finding.canonicalTitle || finding.title)} | ${escapeMarkdown(summarizeFindingRow(finding))} | ${finding.provenance === 'deterministic' ? `Deterministic \`${finding.ruleCode || 'n/a'}\`` : `AI ${Math.round((finding.resolverConfidence ?? finding.confidence) * 100)}%`} |`,
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
                lines.push(`- Evidence: ${getCorroborationDisplayLabel(finding.corroboration ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'UNVERIFIED'))}`);
                lines.push(`- Why it matters: ${finding.explanation || 'No explanation returned.'}`);
                lines.push(`- What to change: ${remediation.remediation}`);
                if (safePattern) {
                    lines.push(`- Safe pattern: ${safePattern}`);
                }
                if (remediation.frameworkVariant) {
                    if (remediation.frameworkVariant.recommendedActions.length) {
                        lines.push(`- Suggested steps: ${remediation.frameworkVariant.recommendedActions.join(' | ')}`);
                    }
                }
                if (remediation.validationSteps.length) {
                    lines.push(`- Validate with: ${remediation.validationSteps.join(' | ')}`);
                }
                if (remediation.unsafeAlternatives.length) {
                    lines.push(`- Avoid: ${remediation.unsafeAlternatives.join(' | ')}`);
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
