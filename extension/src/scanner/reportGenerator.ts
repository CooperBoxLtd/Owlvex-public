import * as path from 'path';
import * as vscode from 'vscode';
import { resolveRemediationForFinding } from '../frameworks/remediationResolver';
import { describeRulePackRuntime, getRulePackModeLabel } from '../packs/packRuntime';
import { ScanResult } from './scanEngine';
import { FolderScanSummary } from './workspaceScanner';

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

function formatMappings(mappings?: NonNullable<ScanResult['findings'][number]['mappings']>): string {
    if (!mappings) return '';

    return ([
        ['CWE', mappings.cwe],
        ['OWASP', mappings.owasp],
        ['API OWASP', mappings.apiOwasp],
        ['ATT&CK', mappings.attack],
        ['CAPEC', mappings.capec],
        ['NIST', mappings.nist],
    ] as Array<[string, string[]]>)
        .filter(([, values]) => values?.length)
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

function getFindingStride(finding: ScanResult['findings'][number]): string[] {
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

// ---------------------------------------------------------------------------
// Report composition helpers
// ---------------------------------------------------------------------------

/**
 * Generates an analyst-facing attack surface assessment paragraph.
 * Derived entirely from finding data — deterministic, no inference.
 */
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
            'This does not guarantee the codebase is free of security issues — ' +
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
            `by deterministic structural analysis** — these are invariant violations in the code structure, ` +
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

/**
 * Builds a compact table of all deterministic findings for prominent display.
 */
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
        'Each represents a confirmed code-level invariant violation — not a heuristic match.',
        '',
        '| Rule | Issue | File | Line | Severity |',
        '| :--- | :--- | :--- | ---: | :--- |',
    ];

    for (const item of sorted) {
        const rule = item.finding.ruleCode || '—';
        const title = escapeMarkdown(item.finding.canonicalTitle || item.finding.title);
        out.push(
            `| ⚡ \`${rule}\` | ${title} | \`${item.file}\` | ${item.finding.line} | **${item.finding.severity}** |`,
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
        }))
    );
    const packModes = new Map<string, number>();
    for (const item of snapshot.results) {
        const label = getRulePackModeLabel(item.result.packContext);
        packModes.set(label, (packModes.get(label) ?? 0) + 1);
    }
    const packCoverageSummary = [...packModes.entries()]
        .map(([label, count]) => `${label}: ${count}`)
        .join(' | ') || 'Bundled Fallback: 0';

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
            if (a.result.score !== b.result.score) return a.result.score - b.result.score;
            return b.result.findings.length - a.result.findings.length;
        })
        .slice(0, 10);

    const topFindings = snapshot.results
        .flatMap(item => item.result.findings.map(finding => ({
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
            finding,
            packContext: item.result.packContext,
        })))
        .sort((a, b) => severityRank(b.finding.severity) - severityRank(a.finding.severity))
        .slice(0, 25);

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

    const allFindingItems = snapshot.results.flatMap(item =>
        item.result.findings.map(finding => ({
            file: path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath),
            finding,
            packContext: item.result.packContext,
        })),
    );
    const deterministicItems = allFindingItems.filter(
        item => item.finding.provenance === 'deterministic',
    );
    const topFamilies = [...findingsByFamily.entries()]
        .sort((a, b) => b[1].length - a[1].length)
        .slice(0, 3)
        .map(([label]) => label)
        .filter(l => l !== 'Unclassified');

    const totalFindings = snapshot.results.reduce(
        (total, item) => total + item.result.findings.length, 0,
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
        `- Total findings: ${snapshot.results.reduce((total, item) => total + item.result.findings.length, 0)}`,
        `- Average score: ${averageScore.toFixed(1)}/10`,
        `- Deterministic findings: ${deterministicItems.length}`,
        `- Intelligence source coverage: ${packCoverageSummary}`,
        `- Errors: ${snapshot.errors.length}`,
        `- Scan warnings: ${warnings.length}`,
        '',
        ...buildAttackSurfaceAssessment(
            totalFindings,
            deterministicItems.length,
            aggregateMetrics,
            topFamilies,
            snapshot.results.length,
            snapshot.results.filter(item => item.result.findings.length > 0).length,
        ),
        ...buildDeterministicPanel(deterministicItems),
        '## Risk Scoring',
        '',
        '- Score meaning: `10` is strongest, `0` is weakest.',
        '- Source of truth: final score is recalculated from finding impact and likelihood, not taken verbatim from the AI model output.',
        '- Impact source: canonical severity is treated as impact: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.',
        '- Likelihood scale: `LOW`, `MEDIUM`, `HIGH`. Missing likelihood defaults to `MEDIUM`.',
        '- Score calculation: `10 - sum(impact penalty x likelihood multiplier)`, floored at `0`.',
        '- Impact penalties: `CRITICAL=3`, `HIGH=2`, `MEDIUM=1`, `LOW=0.5`.',
        '- Likelihood multipliers: `LOW=0.75`, `MEDIUM=1.0`, `HIGH=1.25`.',
        '- Contextual risk matrix: `LOW impact -> 1/2/3`, `MEDIUM -> 3/5/6`, `HIGH -> 5/7/8`, `CRITICAL -> 7/9/10` for `LOW/MEDIUM/HIGH` likelihood.',
        '- Frameworks requested for this scan: `OWASP`, `STRIDE`.',
        '',
        '## Intelligence Source',
        '',
        '- Fresh Packs: backend-served manifest and verified pack artifacts were fetched for this session.',
        '- Cached Packs: previously verified pack artifacts were used because fresh retrieval was unavailable or skipped.',
        '- Bundled Fallback: Owlvex used the shipped local catalog because no verified pack artifacts were available.',
        '',
        '## Severity Breakdown',
        '',
        `- Critical: ${aggregateMetrics.critical}`,
        `- High: ${aggregateMetrics.high}`,
        `- Medium: ${aggregateMetrics.medium}`,
        `- Low: ${aggregateMetrics.low}`,
        '',
        '## Likelihood Breakdown',
        '',
        `- High: ${allFindingItems.filter(item => getFindingLikelihood(item.finding) === 'HIGH').length}`,
        `- Medium: ${allFindingItems.filter(item => getFindingLikelihood(item.finding) === 'MEDIUM').length}`,
        `- Low: ${allFindingItems.filter(item => getFindingLikelihood(item.finding) === 'LOW').length}`,
        '',
        '## Framework Coverage',
        '',
    ];

    if (findingsByFramework.size) {
        for (const [framework, items] of findingsByFramework.entries()) {
            lines.push(`- ${framework}: ${items.length} finding(s)`);
        }
    } else {
        lines.push('- No framework-mapped findings were returned.');
    }

    lines.push('', '## Issue Family Coverage', '');
    if (findingsByFamily.size) {
        for (const [family, items] of [...findingsByFamily.entries()].sort((a, b) => b[1].length - a[1].length)) {
            lines.push(`- ${family}: ${items.length} finding(s)`);
        }
    } else {
        lines.push('- No canonical issue families were resolved.');
    }

    lines.push(
        '',
        '## Riskiest Files',
        '',
        '| File | Score | Findings | Summary |',
        '| --- | ---: | ---: | --- |',
        ...(
            riskyFiles.length
                ? riskyFiles.map(item => {
                    const relative = path.relative(root.fsPath, item.uri.fsPath) || path.basename(item.uri.fsPath);
                    return `| ${escapeMarkdown(relative)} | ${item.result.score.toFixed(1)} | ${item.result.findings.length} | ${escapeMarkdown(summarizeFileResult(item.result))} |`;
                })
                : ['| No files were scanned successfully | - | - | - |']
        ),
        '',
        '## Canonical Findings',
        '',
    );

    if (findingsByCanonicalIssue.size) {
        for (const [issueKey, items] of [...findingsByCanonicalIssue.entries()]
            .sort((a, b) => riskRank(b[1][0].finding) - riskRank(a[1][0].finding))
            .slice(0, 25)) {
            const sample = items[0].finding;
            const packContext = items[0].packContext;
            const remediation = getCanonicalRemediation(sample);
            const isDeterministic = sample.provenance === 'deterministic';
            const provenanceLabel = isDeterministic
                ? `⚡ Deterministic (rule: \`${sample.ruleCode || '—'}\`) — structural invariant, confidence 100%`
                : `🤖 AI-assisted — confidence ${Math.round((sample.resolverConfidence ?? sample.confidence) * 100)}%`;

            lines.push(`### ${sample.severity}: ${sample.canonicalTitle || sample.title}`);
            lines.push(`- Owlvex issue: \`${sample.canonicalId || issueKey}\``);
            lines.push(`- Detection: ${provenanceLabel}`);
            if (sample.canonicalFamilyLabel || sample.canonicalFamily) {
                lines.push(`- Issue family: ${sample.canonicalFamilyLabel || sample.canonicalFamily}`);
            }
            lines.push(`- Category: ${sample.canonicalCategory || 'unresolved'}`);
            lines.push(`- Impact: ${sample.severity}`);
            lines.push(`- Likelihood: ${getFindingLikelihood(sample)}`);
            lines.push(`- Contextual risk: ${sample.riskScore ?? 'n/a'}/10`);
            lines.push(`- Occurrences: ${items.length}`);
            lines.push(`- Files affected: ${new Set(items.map(item => item.file)).size}`);
            lines.push(`- Intelligence source: ${describeRulePackRuntime(packContext)}`);
            if (!isDeterministic) {
                lines.push(`- Confidence: ${Math.round((sample.resolverConfidence ?? sample.confidence) * 100)}%`);
            }
            const sampleStride = getFindingStride(sample);
            if (sampleStride.length) {
                lines.push(`- STRIDE: ${sampleStride.join(', ')}`);
            }
            const sampleSignals = getFindingSignals(sample);
            if (sampleSignals.length) {
                lines.push(`- Matched signals: ${sampleSignals.join(', ')}`);
            }
            const sampleLikelihoodReasons = getFindingLikelihoodReasons(sample);
            if (sampleLikelihoodReasons.length) {
                lines.push(`- Likelihood reasons: ${sampleLikelihoodReasons.join(' | ')}`);
            }
            const mappingSummary = formatMappings(sample.mappings);
            if (mappingSummary) {
                lines.push(`- Framework mappings: ${mappingSummary}`);
            }
            lines.push(`- Summary: ${sample.explanation || 'No explanation returned.'}`);
            lines.push(`- Threat: ${sample.threat || 'No threat description returned.'}`);
            lines.push(`- Recommended fix: ${remediation.remediation}`);
            if (remediation.frameworkVariant) {
                lines.push(`- Framework-specific guidance (${remediation.frameworkVariant.framework}): ${remediation.frameworkVariant.summary}`);
                if (remediation.frameworkVariant.recommendedActions.length) {
                    lines.push(`- Recommended actions: ${remediation.frameworkVariant.recommendedActions.join(' | ')}`);
                }
            }
            if (remediation.validationSteps.length) {
                lines.push(`- Validation steps: ${remediation.validationSteps.join(' | ')}`);
            }
            if (remediation.unsafeAlternatives.length) {
                lines.push(`- Unsafe alternatives to avoid: ${remediation.unsafeAlternatives.join(' | ')}`);
            }
            if (remediation.refs.length) {
                lines.push(`- Remediation sources: ${remediation.refs.join(', ')}`);
            }
            if (remediation.modelNote) {
                lines.push(`- Model implementation note: ${remediation.modelNote}`);
            }
            lines.push('');
        }
    } else {
        lines.push('No findings were returned.');
        lines.push('');
    }

    lines.push('## Detailed Findings by Owlvex Issue', '');

    if (findingsByCanonicalIssue.size) {
        for (const [issueKey, items] of findingsByCanonicalIssue.entries()) {
            const sample = items[0].finding;
            lines.push(`### ${sample.canonicalTitle || sample.title}`);
            lines.push('');
            if (sample.canonicalFamilyLabel || sample.canonicalFamily) {
                lines.push(`- Issue family: ${sample.canonicalFamilyLabel || sample.canonicalFamily}`);
            }
            lines.push(`- Occurrences: ${items.length}`);
            lines.push(`- Files affected: ${new Set(items.map(item => item.file)).size}`);
            lines.push(`- Typical impact: ${sample.severity}`);
            lines.push(`- Typical likelihood: ${getFindingLikelihood(sample)}`);
            lines.push(`- Typical contextual risk: ${sample.riskScore ?? 'n/a'}/10`);
            lines.push('');
            lines.push('#### File-level evidence');
            lines.push('');
            for (const item of items.sort((a, b) => riskRank(b.finding) - riskRank(a.finding))) {
                const snippet = await readCodeSnippet(root, item.file, item.finding.line, item.finding.lineEnd);
                const remediation = getCanonicalRemediation(item.finding);
                lines.push(`- \`${item.file}\` at L${item.finding.line}${item.finding.lineEnd !== item.finding.line ? `-${item.finding.lineEnd}` : ''}`);
                lines.push(`  Impact: ${item.finding.severity}`);
                lines.push(`  Likelihood: ${getFindingLikelihood(item.finding)}`);
                lines.push(`  Contextual risk: ${item.finding.riskScore ?? 'n/a'}/10`);
                lines.push(`  Confidence: ${Math.round((item.finding.resolverConfidence ?? item.finding.confidence) * 100)}%`);
                lines.push(`  Original framework match: ${item.finding.framework}`);
                lines.push(`  Original rule code: ${item.finding.ruleCode || 'n/a'}`);
                lines.push(`  Reasoning: ${item.finding.explanation || 'No explanation returned.'}`);
                lines.push(`  Threat: ${item.finding.threat || 'No threat description returned.'}`);
                const likelihoodReasons = getFindingLikelihoodReasons(item.finding);
                if (likelihoodReasons.length) {
                    lines.push(`  Likelihood reasons: ${likelihoodReasons.join(' | ')}`);
                }
                lines.push(`  Recommended remediation: ${remediation.remediation}`);
                if (remediation.frameworkVariant) {
                    lines.push(`  Framework-specific guidance (${remediation.frameworkVariant.framework}): ${remediation.frameworkVariant.summary}`);
                    if (remediation.frameworkVariant.recommendedActions.length) {
                        lines.push(`  Recommended actions: ${remediation.frameworkVariant.recommendedActions.join(' | ')}`);
                    }
                }
                if (remediation.validationSteps.length) {
                    lines.push(`  Validation steps: ${remediation.validationSteps.join(' | ')}`);
                }
                if (remediation.unsafeAlternatives.length) {
                    lines.push(`  Unsafe alternatives to avoid: ${remediation.unsafeAlternatives.join(' | ')}`);
                }
                if (remediation.modelNote) {
                    lines.push(`  Model implementation note: ${remediation.modelNote}`);
                }
                if (snippet) {
                    lines.push('  Code involved in the reasoning:');
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

    lines.push('## Framework Correlation View', '');
    if (findingsByFramework.size) {
        for (const [framework, items] of findingsByFramework.entries()) {
            lines.push(`### ${framework}`);
            lines.push('');
            for (const item of items.sort((a, b) => riskRank(b.finding) - riskRank(a.finding))) {
                lines.push(`- \`${item.finding.canonicalId || item.finding.ruleCode || item.finding.title}\` in \`${item.file}\` at L${item.finding.line}`);
            }
            lines.push('');
        }
    } else {
        lines.push('No framework correlations were returned.');
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

function severityToScoreImpact(severity: string): string {
    switch (severity) {
        case 'CRITICAL':
            return 'Very high negative impact';
        case 'HIGH':
            return 'High negative impact';
        case 'MEDIUM':
            return 'Moderate negative impact';
        case 'LOW':
            return 'Low negative impact';
        default:
            return 'Unspecified impact';
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
