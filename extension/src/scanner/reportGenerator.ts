import * as path from 'path';
import * as vscode from 'vscode';
import { getGroundedCheatSheetLabelsForIssueIds, resolveRemediationForFinding } from '../frameworks/remediationResolver';
import { describeRulePackRuntime, getRulePackModeLabel } from '../packs/packRuntime';
import { ScanResult } from './scanEngine';
import { FolderScanSummary } from './workspaceScanner';
import { formatFrameworkSummary } from '../frameworks/catalog';
import { formatOwaspMappingForActiveProfile } from '../frameworks/owaspProfile';
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
        ['OWASP', mappings.owasp.map(formatOwaspMappingForActiveProfile), enabled.has('OWASP') || showAllSecurityMappings],
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

function formatEvidencePoint(point: NonNullable<ScanResult['findings'][number]['evidenceContract']>['flow'][number]): string {
    const line = point.line ? `L${point.line}: ` : '';
    return `${point.label} (${line}\`${point.expression}\`)`;
}

function buildEvidenceContractLines(finding: ScanResult['findings'][number], file?: string): string[] {
    const evidence = finding.evidenceContract;
    if (!evidence) {
        return [];
    }

    const lines = [
        `- Evidence contract: ${evidence.verdict} ${evidence.issueType}`,
    ];

    if (evidence.source) {
        lines.push(`  - Source: ${formatEvidencePoint(evidence.source)}`);
    }

    for (const flow of evidence.flow) {
        lines.push(`  - Flow: ${formatEvidencePoint(flow)}`);
    }

    if (evidence.sink) {
        lines.push(`  - Sink: ${formatEvidencePoint(evidence.sink)}`);
    }

    if (evidence.guard) {
        const expression = evidence.guard.expression ? ` (\`${evidence.guard.expression}\`)` : '';
        const line = evidence.guard.line ? ` at L${evidence.guard.line}` : '';
        lines.push(`  - Guard: ${evidence.guard.status} ${evidence.guard.label}${line}${expression}. ${evidence.guard.reason}`);
    }

    lines.push(`  - Rationale: ${evidence.rationale}`);
    lines.push(`  - Proof status: ${getProofStatusDisplayLabel(getFindingProofStatus(finding, file))}`);
    if (evidence.attackerAction) {
        lines.push(`  - Attacker action: ${evidence.attackerAction}`);
    }
    if (evidence.requiredGuard?.length) {
        lines.push(`  - Required guard: ${evidence.requiredGuard.join(' | ')}`);
    }
    if (evidence.counterEvidence?.length) {
        lines.push(`  - Counter-evidence checked: ${evidence.counterEvidence.join(' | ')}`);
    }
    if (evidence.responsibilityLayer) {
        lines.push(`  - Responsibility layer: ${evidence.responsibilityLayer}`);
    }
    for (const check of evidence.proofChecks ?? []) {
        lines.push(`  - Proof check: ${check.status} ${check.check}${check.evidence ? ` (${check.evidence})` : ''}`);
    }
    return lines;
}

function buildSafeProbeLines(finding: ScanResult['findings'][number]): string[] {
    const probe = finding.safeProbe;
    if (!probe) {
        return [];
    }

    const lines = [
        '- Safe exploit probe: simulated',
        '- Sink execution: intercepted',
        `- Probe techniques: ${probe.techniques.join(', ')}`,
        `- Probe verdict: ${probe.verdict.replace(/_/g, ' ')}`,
        `- Probe decision: ${probe.decision.replace(/_/g, ' ')}`,
        `- Probe sink: ${probe.sinkKind}${probe.sinkLine ? ` at L${probe.sinkLine}` : ''}`,
        `- Canary reached sink: ${probe.canaryReachedSink ? 'yes' : 'no'}`,
        `- Guard observed: ${probe.guardStatus}${probe.guardKind ? ` ${probe.guardKind}` : ''}`,
        `- Probe reason: ${probe.reason}`,
    ];
    if (probe.canary) {
        lines.push(`- Canary: ${probe.canary}`);
    }
    if (probe.counterexample) {
        const parts = [
            probe.counterexample.unsafeInput ? `unsafe input \`${probe.counterexample.unsafeInput}\`` : '',
            probe.counterexample.safeInput ? `safe input \`${probe.counterexample.safeInput}\`` : '',
            typeof probe.counterexample.unsafeBlocked === 'boolean' ? `unsafe blocked: ${probe.counterexample.unsafeBlocked ? 'yes' : 'no'}` : '',
            typeof probe.counterexample.safeAllowed === 'boolean' ? `safe allowed: ${probe.counterexample.safeAllowed ? 'yes' : 'no'}` : '',
        ].filter(Boolean);
        if (parts.length) {
            lines.push(`- Counterexample probe: ${parts.join(' | ')}`);
        }
    }
    if (probe.executionSlice) {
        lines.push(`- Execution slice: ${probe.executionSlice.kind}${probe.executionSlice.target ? ` (${probe.executionSlice.target})` : ''}; dangerous capabilities blocked: ${probe.executionSlice.dangerousCapabilitiesBlocked ? 'yes' : 'no'}`);
    }
    if (probe.taintTrace?.length) {
        lines.push(`- Taint trace: ${probe.taintTrace.join(' -> ')}`);
    }
    if (probe.mutationCount) {
        lines.push(`- Mutation probes: ${probe.mutationCount}`);
    }
    if (probe.differentialTarget) {
        lines.push(`- Differential target: ${probe.differentialTarget}`);
    }
    if (probe.fixVerificationReady) {
        lines.push('- Fix verification probe: ready after Keep fix');
    }
    if (probe.contextDepth) {
        lines.push(`- Probe context: ${probe.contextDepth}`);
    }

    return lines;
}

type ProofStatus = NonNullable<NonNullable<ScanResult['findings'][number]['evidenceContract']>['proofStatus']>;

function getFindingProofStatus(finding: ScanResult['findings'][number], file?: string): ProofStatus {
    if (isLikelyUnprovenHelperFinding(finding, file)) {
        return 'unproven_extra';
    }

    if (finding.proofStatus) {
        return finding.proofStatus;
    }

    if (finding.evidenceContract?.proofStatus) {
        return finding.evidenceContract.proofStatus;
    }

    if (finding.provenance === 'deterministic') {
        return 'static_proven';
    }

    const evidence = finding.evidenceContract;
    if (evidence?.source?.expression && evidence.sink?.expression && evidence.guard?.status === 'missing') {
        return 'ai_plausible';
    }

    return 'unproven_extra';
}

function getProofStatusDisplayLabel(status: ProofStatus): string {
    switch (status) {
        case 'static_proven':
            return 'Static proven';
        case 'ai_plausible':
            return 'AI plausible with source/sink/guard evidence';
        case 'counter_evidence_found':
            return 'Counter-evidence found';
        case 'unproven_extra':
            return 'Unproven extra';
    }
}

function isLikelyUnprovenHelperFinding(finding: ScanResult['findings'][number], file?: string): boolean {
    const haystack = [
        file ?? '',
        finding.title,
        finding.canonicalTitle ?? '',
        finding.canonicalFamilyLabel ?? '',
        finding.canonicalFamily ?? '',
        finding.evidenceContract?.issueType ?? '',
    ].join(' ').toLowerCase();

    if (/middleware[\\/]+auth\.js/.test(haystack)) {
        return /\baudit\b|\blog\b|ownership|authorization|auth/.test(haystack);
    }

    if (/lib[\\/]+auditlogger\.js/.test(haystack)) {
        return /\baudit\b|\blog\b|sensitive/.test(haystack);
    }

    if (/store[\\/]+repositories\.js/.test(haystack)) {
        return /\baudit\b|authorization|missing[_ -]?authorization|privilege|role/.test(haystack);
    }

    return false;
}

function isPromotedFinding(finding: ScanResult['findings'][number], file?: string): boolean {
    const status = getFindingProofStatus(finding, file);
    return status === 'static_proven' || status === 'ai_plausible';
}

function summarizeProofPosture(findings: ScanResult['findings'], file?: string): string {
    if (!findings.length) {
        return 'No findings to prove.';
    }

    const counts = new Map<ProofStatus, number>();
    for (const finding of findings) {
        const status = getFindingProofStatus(finding, file);
        counts.set(status, (counts.get(status) ?? 0) + 1);
    }

    return [
        `static proven: ${counts.get('static_proven') ?? 0}`,
        `AI plausible: ${counts.get('ai_plausible') ?? 0}`,
        `counter-evidence: ${counts.get('counter_evidence_found') ?? 0}`,
        `unproven extras: ${counts.get('unproven_extra') ?? 0}`,
    ].join(' | ');
}

function summarizeEngineEvidence(findings: ScanResult['findings']): string {
    if (!findings.length) {
        return 'No findings to prove.';
    }

    const withContracts = findings.filter(finding => finding.evidenceContract);
    const confirmed = withContracts.filter(finding => finding.evidenceContract?.verdict === 'confirmed');
    const missingGuards = withContracts.filter(finding => finding.evidenceContract?.guard?.status === 'missing');
    const deterministicWithoutContract = findings.filter(finding => finding.provenance === 'deterministic' && !finding.evidenceContract);
    const aiWithoutContract = findings.filter(finding => finding.provenance !== 'deterministic' && !finding.evidenceContract);

    return [
        `Structured contracts: ${withContracts.length}/${findings.length}`,
        `confirmed: ${confirmed.length}`,
        `missing guards: ${missingGuards.length}`,
        `deterministic gaps: ${deterministicWithoutContract.length}`,
        `AI without contract: ${aiWithoutContract.length}`,
    ].join(' | ');
}

function aggregateEngineTelemetry(results: ReportEntry[]): NonNullable<ScanResult['engineTelemetry']> | undefined {
    const entries = results
        .map(item => item.result.engineTelemetry)
        .filter((telemetry): telemetry is NonNullable<ScanResult['engineTelemetry']> => Boolean(telemetry));
    if (!entries.length) {
        return undefined;
    }

    const aggregate: NonNullable<ScanResult['engineTelemetry']> = {
        sinkInventory: {
            total: 0,
            byFamily: {},
            guarded: 0,
            missingGuard: 0,
            unknownGuard: 0,
        },
        aiFindings: {
            proposed: 0,
            afterStaticFilter: 0,
            afterCorroboration: 0,
            finalSurvivors: 0,
        },
        safeProbes: {
            run: 0,
            confirmed: 0,
            counterEvidence: 0,
            unsupported: 0,
            inconclusive: 0,
            promoted: 0,
            downgraded: 0,
            dropped: 0,
            manualReview: 0,
        },
        corroborationRouting: {
            verifierRequested: 0,
            verifierSkippedSafeProbeConfirmed: 0,
            verifierSkippedHighConfidence: 0,
            verifierSkippedLowSignal: 0,
            skepticRequested: 0,
            skepticSkippedNoVerifier: 0,
            skepticSkippedVerifierRejected: 0,
            skepticSkippedStrongSupport: 0,
            skepticSkippedStable: 0,
        },
    };

    for (const entry of entries) {
        aggregate.sinkInventory.total += entry.sinkInventory.total;
        aggregate.sinkInventory.guarded += entry.sinkInventory.guarded;
        aggregate.sinkInventory.missingGuard += entry.sinkInventory.missingGuard;
        aggregate.sinkInventory.unknownGuard += entry.sinkInventory.unknownGuard;
        for (const [family, count] of Object.entries(entry.sinkInventory.byFamily)) {
            const key = family as keyof typeof aggregate.sinkInventory.byFamily;
            aggregate.sinkInventory.byFamily[key] = (aggregate.sinkInventory.byFamily[key] ?? 0) + Number(count ?? 0);
        }
        aggregate.aiFindings.proposed += entry.aiFindings.proposed;
        aggregate.aiFindings.afterStaticFilter += entry.aiFindings.afterStaticFilter;
        aggregate.aiFindings.afterCorroboration += entry.aiFindings.afterCorroboration;
        aggregate.aiFindings.finalSurvivors += entry.aiFindings.finalSurvivors;
        aggregate.safeProbes.run += entry.safeProbes.run;
        aggregate.safeProbes.confirmed += entry.safeProbes.confirmed;
        aggregate.safeProbes.counterEvidence += entry.safeProbes.counterEvidence;
        aggregate.safeProbes.unsupported += entry.safeProbes.unsupported;
        aggregate.safeProbes.inconclusive += entry.safeProbes.inconclusive;
        aggregate.safeProbes.promoted += entry.safeProbes.promoted;
        aggregate.safeProbes.downgraded += entry.safeProbes.downgraded;
        aggregate.safeProbes.dropped += entry.safeProbes.dropped;
        aggregate.safeProbes.manualReview += entry.safeProbes.manualReview;
        aggregate.corroborationRouting!.verifierRequested += entry.corroborationRouting?.verifierRequested ?? 0;
        aggregate.corroborationRouting!.verifierSkippedSafeProbeConfirmed += entry.corroborationRouting?.verifierSkippedSafeProbeConfirmed ?? 0;
        aggregate.corroborationRouting!.verifierSkippedHighConfidence += entry.corroborationRouting?.verifierSkippedHighConfidence ?? 0;
        aggregate.corroborationRouting!.verifierSkippedLowSignal += entry.corroborationRouting?.verifierSkippedLowSignal ?? 0;
        aggregate.corroborationRouting!.skepticRequested += entry.corroborationRouting?.skepticRequested ?? 0;
        aggregate.corroborationRouting!.skepticSkippedNoVerifier += entry.corroborationRouting?.skepticSkippedNoVerifier ?? 0;
        aggregate.corroborationRouting!.skepticSkippedVerifierRejected += entry.corroborationRouting?.skepticSkippedVerifierRejected ?? 0;
        aggregate.corroborationRouting!.skepticSkippedStrongSupport += entry.corroborationRouting?.skepticSkippedStrongSupport ?? 0;
        aggregate.corroborationRouting!.skepticSkippedStable += entry.corroborationRouting?.skepticSkippedStable ?? 0;
    }

    return aggregate;
}

function formatSinkFamilyCounts(telemetry: NonNullable<ScanResult['engineTelemetry']> | undefined): string {
    const entries = Object.entries(telemetry?.sinkInventory.byFamily ?? {})
        .filter(([, count]) => Number(count) > 0)
        .sort(([left], [right]) => left.localeCompare(right));
    return entries.length
        ? entries.map(([family, count]) => `${family}: ${count}`).join(' | ')
        : 'none';
}

function buildProbeQualitySignal(telemetry: NonNullable<ScanResult['engineTelemetry']>): string {
    const safeProbes = telemetry.safeProbes;
    const resolved = safeProbes.confirmed + safeProbes.counterEvidence + safeProbes.unsupported;
    const resolutionRate = safeProbes.run > 0
        ? Math.round((resolved / safeProbes.run) * 100)
        : 0;
    const removedBeforeReport = safeProbes.dropped + safeProbes.downgraded;

    return [
        `- Probe quality signal: resolved ${resolved}/${safeProbes.run} (${resolutionRate}%)`,
        `confirmed paths ${safeProbes.confirmed}`,
        `AI candidates removed or downgraded ${removedBeforeReport}`,
        `manual review residue ${safeProbes.inconclusive + safeProbes.manualReview}`,
    ].join(' | ');
}

function buildEngineTelemetryLines(telemetry: NonNullable<ScanResult['engineTelemetry']> | undefined): string[] {
    if (!telemetry) {
        return [];
    }

    const routing = telemetry.corroborationRouting;
    const lines = [
        `- Local sinks discovered before AI: ${telemetry.sinkInventory.total} (${formatSinkFamilyCounts(telemetry)})`,
        `- Sink guard posture: guarded ${telemetry.sinkInventory.guarded} | missing guard ${telemetry.sinkInventory.missingGuard} | unknown ${telemetry.sinkInventory.unknownGuard}`,
        `- AI finding funnel: proposed ${telemetry.aiFindings.proposed} | after static/sink/probe filter ${telemetry.aiFindings.afterStaticFilter} | after corroboration ${telemetry.aiFindings.afterCorroboration} | final AI survivors ${telemetry.aiFindings.finalSurvivors}`,
        `- Safe probes: run ${telemetry.safeProbes.run} | confirmed ${telemetry.safeProbes.confirmed} | counter-evidence ${telemetry.safeProbes.counterEvidence} | unsupported ${telemetry.safeProbes.unsupported} | inconclusive ${telemetry.safeProbes.inconclusive}`,
        `- Probe decisions: promoted ${telemetry.safeProbes.promoted} | downgraded ${telemetry.safeProbes.downgraded} | dropped ${telemetry.safeProbes.dropped} | manual review ${telemetry.safeProbes.manualReview}`,
    ];

    if (routing) {
        lines.push(
            `- AI corroboration routing: verifier requested ${routing.verifierRequested} | skipped safe-probe-confirmed ${routing.verifierSkippedSafeProbeConfirmed} | skipped high-confidence ${routing.verifierSkippedHighConfidence} | skipped low-signal ${routing.verifierSkippedLowSignal} | skeptic requested ${routing.skepticRequested} | skipped no-verifier ${routing.skepticSkippedNoVerifier} | skipped verifier-rejected ${routing.skepticSkippedVerifierRejected} | skipped strong-support ${routing.skepticSkippedStrongSupport} | skipped stable ${routing.skepticSkippedStable}`,
        );
    }
    if (telemetry.callerPathRouting) {
        const caller = telemetry.callerPathRouting;
        lines.push(
            `- Caller-path routing: requested ${caller.requested} | skipped ${caller.skipped} | callers ${caller.callersFound} | guarded ${caller.guardedCallers} | unguarded ${caller.unguardedCallers} | unknown ${caller.unknownCallers}`,
        );
    }
    if (telemetry.actionGating) {
        const gating = telemetry.actionGating;
        lines.push(
            `- Action gating: fix-preview eligible ${gating.fixPreviewEligible} | investigation-first ${gating.investigationFirst} | manual-review ${gating.manualReview} | suppressed ${gating.suppressed}`,
        );
    }

    lines.push(buildProbeQualitySignal(telemetry));
    return lines;
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

function hasAiReviewPass(finding: ScanResult['findings'][number], pass: 'verifier' | 'skeptic'): boolean {
    const score = finding.aiReviewScores?.[pass];
    return typeof score === 'number' && Number.isFinite(score);
}

function hasIndependentAiReview(finding: ScanResult['findings'][number]): boolean {
    return hasAiReviewPass(finding, 'verifier') || hasAiReviewPass(finding, 'skeptic');
}

function hasNonScoringAiReviewNote(finding: ScanResult['findings'][number], pass: 'verifier' | 'skeptic'): boolean {
    return Boolean(finding.aiReviewNotes?.[pass]) && !hasAiReviewPass(finding, pass);
}

function getAiReviewPathLabel(finding: ScanResult['findings'][number]): string {
    const passes = ['finder'];
    if (hasAiReviewPass(finding, 'verifier')) {
        passes.push('verifier');
    }
    if (hasAiReviewPass(finding, 'skeptic')) {
        passes.push('skeptic');
    }
    const path = passes.join('+');
    const noVerdict = [
        hasNonScoringAiReviewNote(finding, 'verifier') ? 'verifier no verdict' : '',
        hasNonScoringAiReviewNote(finding, 'skeptic') ? 'skeptic no verdict' : '',
    ].filter(Boolean);
    return noVerdict.length ? `${path} (${noVerdict.join(', ')})` : path;
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

function getProviderComparisonNotes(results: ReportEntry[]): string[] {
    return [...new Set(results.flatMap(item => item.result.providerComparisonNotes ?? []))];
}

function getProviderDisagreementProofLines(root: vscode.Uri, results: ReportEntry[]): string[] {
    return results.flatMap(item =>
        (item.result.providerDisagreementProofs ?? []).map(proof => {
            const parts = [
                proof.reason,
                proof.issueType ? `issue ${proof.issueType}` : '',
                proof.source ? `source \`${proof.source}\`` : '',
                proof.sink ? `sink \`${proof.sink}\`` : '',
                proof.guard ? `guard ${proof.guard}` : '',
            ].filter(Boolean).join(' | ');
            return `${formatReportPath(root.fsPath, item.uri.fsPath)}: ${proof.verdict}${parts ? ` - ${parts}` : ''}`;
        }),
    );
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
    const evidence = getEvidenceDisplayLabel(finding);
    const reviewFlag = needsManualReview(finding) ? ' | manual review recommended' : '';
    const parts = [
        `mode ${scanTier}`,
        `confidence ${confidence}`,
        `evidence ${evidence}`,
    ];

    if (finding.provenance !== 'deterministic') {
        parts.push(`AI signal ${getConfidenceBand(getAiConfidence(finding))} (${formatPercent(getAiConfidence(finding))} final)`);
        parts.push(`review path ${getAiReviewPathLabel(finding)}`);
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

function getConfidenceBand(value: number | undefined): string {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return 'Unknown';
    }
    if (value >= 0.85) {
        return 'High';
    }
    if (value >= 0.7) {
        return 'Medium';
    }
    return 'Low';
}

function formatAiPassBandSummary(finding: ScanResult['findings'][number]): string {
    const scores = finding.aiReviewScores;
    const finder = scores?.finder ?? finding.resolverConfidence ?? finding.confidence;
    const final = scores?.final ?? getAiConfidence(finding);
    const bands = [
        `finder ${getConfidenceBand(finder)}`,
        `verifier ${getConfidenceBand(scores?.verifier)}`,
        `skeptic ${getConfidenceBand(scores?.skeptic)}`,
        `final ${getConfidenceBand(final)}`,
    ].join(' | ');
    return `${bands} (raw audit: finder ${formatPercent(finder)}, verifier ${formatPercent(scores?.verifier)}, skeptic ${formatPercent(scores?.skeptic)}, final ${formatPercent(final)})`;
}

function formatEvidenceConfidence(finding: ScanResult['findings'][number]): string {
    if (finding.provenance === 'deterministic') {
        return `Confirmed by rule \`${finding.ruleCode || 'n/a'}\``;
    }

    const confidence = getConfidenceBand(getAiConfidence(finding));
    const evidence = getEvidenceDisplayLabel(finding);
    const manual = needsManualReview(finding) ? '; manual review recommended' : '';
    return `${confidence} AI signal, final ${formatPercent(getAiConfidence(finding))} (${getAiReviewPathLabel(finding)}; ${evidence}${manual})`;
}

function getBaseFindingTitle(finding: ScanResult['findings'][number]): string {
    const title = finding.canonicalTitle || finding.title;
    const evidenceIssueType = finding.evidenceContract?.issueType ?? '';
    if (
        /pii|sensitive[-_ ]?response|sensitive[-_ ]?data|over[-_ ]?exposure|overexposure/i.test(evidenceIssueType)
        && /graphql|introspection/i.test(title)
    ) {
        return 'PII or sensitive fields over-exposed in API response';
    }

    if (/missing audit trail for privileged action/i.test(title)) {
        const source = finding.evidenceContract?.source?.expression ?? '';
        if (/updateEmail\s*\(/i.test(source)) {
            return 'Missing audit trail for account profile change';
        }
        if (/updateRole\s*\(/i.test(source)) {
            return 'Missing audit trail for role change';
        }
        if (/approve\s*\(/i.test(source)) {
            return 'Missing audit trail for refund approval';
        }
    }

    return finding.canonicalTitle || finding.title;
}

function getEvidenceAnchor(finding: ScanResult['findings'][number]): string | undefined {
    const source = finding.evidenceContract?.source?.expression?.trim();
    if (source) {
        return source;
    }

    return finding.evidenceContract?.sink?.expression?.trim();
}

function getFindingDisplayTitle(
    finding: ScanResult['findings'][number],
    peerFindings: ScanResult['findings'] = [],
): string {
    const title = getBaseFindingTitle(finding);
    const duplicateTitleCount = peerFindings.filter(peer => getBaseFindingTitle(peer) === title).length;
    const anchor = getEvidenceAnchor(finding);
    if ((duplicateTitleCount > 1 || /missing audit trail/i.test(title)) && anchor) {
        return `${title} (${anchor})`;
    }

    return title;
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

function getEvidenceCountBucket(finding: ScanResult['findings'][number]): 'PROVEN' | 'CORROBORATED' | 'FINDER_ONLY' | 'PARTIAL' | 'UNVERIFIED' {
    const label = getCorroborationLabel(finding);
    if (finding.provenance !== 'deterministic' && !hasIndependentAiReview(finding) && (label === 'CORROBORATED' || label === 'UNVERIFIED')) {
        return 'FINDER_ONLY';
    }
    if (label === 'PROVEN' || label === 'CORROBORATED' || label === 'PARTIAL' || label === 'UNVERIFIED') {
        return label;
    }
    return 'UNVERIFIED';
}

function summarizeCorroborationCounts(findings: ScanResult['findings']): string {
    const order: Array<'PROVEN' | 'CORROBORATED' | 'FINDER_ONLY' | 'PARTIAL' | 'UNVERIFIED'> = ['PROVEN', 'CORROBORATED', 'FINDER_ONLY', 'PARTIAL', 'UNVERIFIED'];
    const counts = new Map<string, number>();

    for (const finding of findings) {
        const label = getEvidenceCountBucket(finding);
        counts.set(label, (counts.get(label) ?? 0) + 1);
    }

    return order
        .filter(label => (counts.get(label) ?? 0) > 0)
        .map(label => `${label.toLowerCase().replace('_', '-')}: ${counts.get(label)}`)
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

function getEvidenceDisplayLabel(finding: ScanResult['findings'][number]): string {
    if (finding.provenance === 'deterministic') {
        return getCorroborationDisplayLabel(finding.corroboration ?? 'PROVEN');
    }

    const corroboration = finding.corroboration ?? 'UNVERIFIED';
    if (finding.safeProbe?.verdict === 'confirmed' && !hasIndependentAiReview(finding)) {
        return 'Validated by safe probe';
    }

    if (corroboration === 'CORROBORATED' && !hasIndependentAiReview(finding)) {
        return 'Finder high confidence, not independently verified';
    }

    if (corroboration === 'UNVERIFIED' && !hasIndependentAiReview(finding)) {
        return 'Finder-only AI review';
    }

    return getCorroborationDisplayLabel(corroboration);
}

function buildHowToReadTable(): string[] {
    return [
        '## How To Read This Report',
        '',
        '| Report field | What it means | How to use it |',
        '| --- | --- | --- |',
        '| Confidence | Evidence posture for the finding, not an exact probability | Use this as a triage signal, not a mathematical certainty |',
        '| Confirmed by rule | Deterministic analysis proved the issue from code structure | Highest confidence |',
        '| Validated by AI review | AI found the issue and verifier or skeptic review also supported it | Strong signal, but not rule-proven |',
        '| Validated by safe probe | AI found the issue and a local non-executing probe confirmed the modeled source-to-sink path | Strong local signal; still not live exploit execution |',
        '| Finder-only AI review | The finder reported the issue, but verifier and skeptic were not triggered or were unavailable | Treat as model-backed evidence, not independent validation |',
        '| Finder high confidence, not independently verified | The finder score is high, but no verifier or skeptic pass is present in the audit trail | Useful triage signal; validate important fixes against the code |',
        '| Partially validated | Some supporting evidence exists, but verification was incomplete | Review before acting |',
        '| Needs manual review | Evidence is weak, incomplete, or low-confidence | Do not treat as confirmed yet |',
        '| Possible Extra | Risky helper-layer sink or unproven hypothesis that is not promoted to Fix First | Trace caller path or verify reachability before patching |',
        '| Action gating | Whether the finding is eligible for Preview fix or should be investigated first | Use Preview fix for proof-supported findings; use caller-path actions for investigation-first items |',
        '| Caller-path verdict | Whether Owlvex found guarded, unguarded, mixed, missing, or unknown callers for a helper sink | Promote only unsafe reachable paths; keep guarded/unknown helpers as review items |',
        '| AI signal | Qualitative band plus final raw confidence from the model review trail | Use with the evidence label; the percentage is model confidence, not proof |',
        '| Impact | How serious the damage could be if exploited | Business/security severity |',
        '| Likelihood | How likely exploitation is from the observed code | Exploitability estimate |',
        '| Risk score | Overall priority if the finding is real | Use this to prioritize fixes |',
        '| Evidence confidence | Rule proof or qualitative AI signal for the detection | Separate from risk score |',
        '| Frameworks in scope | Frameworks selected for AI grounding, mapping display, and report emphasis | Deterministic evidence rules may still identify security issues that map to other frameworks; those mappings are reference taxonomy, not proof that every framework lens was used |',
        '',
    ];
}

function getSelectedFrameworks(results: ReportSnapshot['results']): string[] {
    return [...new Set(results.flatMap(item => item.result.frameworks ?? []))];
}

function buildFrameworkScopeLines(results: ReportSnapshot['results']): string[] {
    const selectedSummary = formatFrameworkSummary(getSelectedFrameworks(results));
    return [
        `- Selected framework lens: ${selectedSummary || 'none recorded'}`,
        '- Framework selection controls AI grounding, report emphasis, remediation variants, and which mapping families are expanded in detail.',
        '- Deterministic evidence rules still run security-first. If code evidence proves an issue, Owlvex may show canonical mappings such as CWE, OWASP, MITRE, or NIST even when that framework was not selected.',
        '- Treat unselected-framework mappings as reference taxonomy for the finding, not as evidence that Owlvex scanned with every framework lens enabled.',
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
    const firstRiskyFile = findingsByFile.find(item => item.result.findings.some(finding => isPromotedFinding(finding, item.file)));
    if (!firstRiskyFile) {
        const hasUnpromotedFindings = findingsByFile.some(item => item.result.findings.length > 0);
        return hasUnpromotedFindings
            ? 'Start with: no proof-promoted findings; review Possible Extra Findings before acting.'
            : 'Start with: no active findings were identified in this scan.';
    }

    const promoted = firstRiskyFile.result.findings.filter(finding => isPromotedFinding(finding, firstRiskyFile.file));
    const topFinding = [...promoted]
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

function collectDesignContext(results: Array<{ result: ScanResult }>): NonNullable<ScanResult['designContext']>[] {
    const seen = new Set<string>();
    const contexts: NonNullable<ScanResult['designContext']>[] = [];
    for (const item of results) {
        const design = item.result.designContext;
        if (!design) {
            continue;
        }
        const key = JSON.stringify({
            loaded: design.loaded,
            files: design.files,
            strideSelected: design.strideSelected,
            missingForStride: design.missingForStride,
        });
        if (!seen.has(key)) {
            seen.add(key);
            contexts.push(design);
        }
    }
    return contexts;
}

function buildDesignContextLabel(results: Array<{ result: ScanResult }>): string {
    const contexts = collectDesignContext(results);
    if (!contexts.length) {
        return 'not checked';
    }
    if (contexts.some(context => context.loaded)) {
        const files = [...new Set(contexts.flatMap(context => context.files))];
        return files.length
            ? `loaded ${files.length} file${files.length === 1 ? '' : 's'} (${files.join(', ')})`
            : 'loaded';
    }
    if (contexts.some(context => context.missingForStride)) {
        return 'missing while STRIDE selected';
    }
    return 'none';
}

function buildDesignContextReportLines(results: Array<{ result: ScanResult }>): string[] {
    const contexts = collectDesignContext(results);
    if (!contexts.length) {
        return ['- Design context: not checked'];
    }

    const files = [...new Set(contexts.flatMap(context => context.files))];
    const lines = [`- Design context: ${buildDesignContextLabel(results)}`];
    if (files.length) {
        for (const file of files.slice(0, 8)) {
            lines.push(`  - Used: \`${file}\``);
        }
    }
    if (contexts.some(context => context.missingForStride)) {
        lines.push('- STRIDE design note: STRIDE was selected, but no `.owlvex/design` markdown or text context was loaded. STRIDE review has limited architecture/trust-boundary grounding.');
    }
    return lines;
}

function collectDesignMaps(results: Array<{ result: ScanResult }>): NonNullable<ScanResult['designMap']>[] {
    const seen = new Set<string>();
    const maps: NonNullable<ScanResult['designMap']>[] = [];
    for (const item of results) {
        const designMap = item.result.designMap;
        if (!designMap?.loaded) {
            continue;
        }
        const key = designMap.path ?? 'loaded';
        if (!seen.has(key)) {
            seen.add(key);
            maps.push(designMap);
        }
    }
    return maps;
}

function buildDesignMapLabel(results: Array<{ result: ScanResult }>): string {
    const maps = collectDesignMaps(results);
    if (!maps.length) {
        return '';
    }
    const paths = maps.map(map => map.path).filter((value): value is string => Boolean(value));
    return paths.length
        ? `loaded ${paths.length} map${paths.length === 1 ? '' : 's'} (${paths.join(', ')})`
        : 'loaded';
}

function buildDesignMapOverviewLines(results: Array<{ result: ScanResult }>): string[] {
    const label = buildDesignMapLabel(results);
    return label ? [`- Design Map: ${label}`] : [];
}

function buildDesignMapReportLines(results: Array<{ result: ScanResult }>): string[] {
    const maps = collectDesignMaps(results);
    if (!maps.length) {
        return [];
    }

    const lines = [`- Design Map: ${buildDesignMapLabel(results)}`];
    for (const path of maps.map(map => map.path).filter((value): value is string => Boolean(value)).slice(0, 8)) {
        lines.push(`  - Used: \`${path}\``);
    }
    return lines;
}

function collectDriftBoxes(results: Array<{ result: ScanResult }>): NonNullable<ScanResult['driftBox']>[] {
    const seen = new Set<string>();
    const boxes: NonNullable<ScanResult['driftBox']>[] = [];
    for (const item of results) {
        const driftBox = item.result.driftBox;
        if (!driftBox) {
            continue;
        }
        const key = [
            driftBox.configPath ?? '',
            driftBox.summary,
            driftBox.checks.map(check => `${check.id}:${check.status}:${check.reason ?? ''}`).join('|'),
        ].join('::');
        if (!seen.has(key)) {
            seen.add(key);
            boxes.push(driftBox);
        }
    }
    return boxes;
}

function buildDriftBoxLabel(results: Array<{ result: ScanResult }>): string {
    const boxes = collectDriftBoxes(results);
    if (!boxes.length) {
        return 'not checked';
    }
    if (!boxes.some(box => box.found)) {
        return boxes[0].summary || 'no drift box';
    }

    return boxes
        .map(box => box.configPath ? `${box.summary} (${box.configPath})` : box.summary)
        .join(' | ');
}

function hasReportableDrift(results: Array<{ result: ScanResult }>): boolean {
    return collectDriftRunResults(results).length > 0
        || collectDriftBoxes(results).some(box => box.found && box.checks.some(check => check.status === 'ready'));
}

function buildDriftOverviewLines(results: Array<{ result: ScanResult }>): string[] {
    if (!hasReportableDrift(results)) {
        return [];
    }
    return [
        `- Drift Box: ${buildDriftBoxLabel(results)}`,
        `- Drift run: ${buildDriftRunLabel(results)}`,
    ];
}

function buildDriftBoxReportLines(results: Array<{ result: ScanResult }>): string[] {
    const boxes = collectDriftBoxes(results);
    if (!hasReportableDrift(results)) {
        return [];
    }

    const lines: string[] = [];
    for (const box of boxes) {
        lines.push(`- Drift Box: ${box.summary}`);
        if (box.configPath) {
            lines.push(`- Drift config: \`${box.configPath}\``);
        }
        if (!box.found) {
            continue;
        }
        const ready = box.checks.filter(check => check.status === 'ready').length;
        const invalid = box.checks.filter(check => check.status === 'invalid').length;
        const disabled = box.checks.filter(check => check.status === 'disabled').length;
        const outOfScope = box.checks.filter(check => check.status === 'out_of_scope').length;
        lines.push(`- Drift checks: ready ${ready} | invalid ${invalid} | disabled ${disabled} | out of scope ${outOfScope}`);
        for (const check of box.checks.slice(0, 10)) {
            const tags = [
                check.frameworks.length ? `legacy tags ${check.frameworks.join(', ')}` : 'custom behavior check',
                `scope ${check.scope.join(', ')}`,
                `${check.timeoutSeconds}s`,
            ].join(' | ');
            lines.push(`  - ${check.status}: ${check.id} (${check.label}) | ${tags}${check.reason ? ` | ${check.reason}` : ''}`);
        }
        if (box.checks.length > 10) {
            lines.push(`  - ${box.checks.length - 10} additional drift check(s) omitted from report detail.`);
        }
        for (const warning of box.warnings.slice(0, 5)) {
            lines.push(`  - Warning: ${warning}`);
        }
    }
    return lines;
}

function collectDriftRunResults(results: Array<{ result: ScanResult }>): NonNullable<ScanResult['driftResults']> {
    const seen = new Set<string>();
    const driftResults: NonNullable<ScanResult['driftResults']> = [];
    for (const item of results) {
        for (const result of item.result.driftResults ?? []) {
            const key = [
                result.id,
                result.status,
                result.exitCode ?? '',
                result.reason ?? '',
                result.stdout,
                result.stderr,
            ].join('::');
            if (!seen.has(key)) {
                seen.add(key);
                driftResults.push(result);
            }
        }
    }
    return driftResults;
}

function buildDriftRunLabel(results: Array<{ result: ScanResult }>): string {
    const driftResults = collectDriftRunResults(results);
    if (!driftResults.length) {
        return 'not run';
    }

    const count = (status: string) => driftResults.filter(result => result.status === status).length;
    return [
        `passed ${count('passed')}`,
        `failed ${count('failed')}`,
        `timed out ${count('timed_out')}`,
        `not approved ${count('not_approved')}`,
        `skipped ${count('skipped')}`,
    ].join(' | ');
}

function buildDriftRunReportLines(results: Array<{ result: ScanResult }>): string[] {
    const driftResults = collectDriftRunResults(results);
    if (!driftResults.length) {
        return [];
    }

    return [
        `- Drift run: ${buildDriftRunLabel(results)}`,
        ...driftResults.slice(0, 10).map(result => {
            const details = [
                `${result.durationMs}ms`,
                typeof result.exitCode !== 'undefined' ? `exit ${result.exitCode ?? 'n/a'}` : '',
                result.reason ? result.reason : '',
            ].filter(Boolean).join(' | ');
            const output = [
                result.stdout ? `stdout: ${result.stdout.trim().slice(0, 180)}` : '',
                result.stderr ? `stderr: ${result.stderr.trim().slice(0, 180)}` : '',
            ].filter(Boolean).join(' | ');
            return `  - ${result.status}: ${result.id} (${result.label})${details ? ` | ${details}` : ''}${output ? ` | ${output}` : ''}`;
        }),
        ...(driftResults.length > 10 ? [`  - ${driftResults.length - 10} additional drift result(s) omitted from report detail.`] : []),
    ];
}

function buildConfidencePostureLine(
    findings: ScanResult['findings'],
): string {
    if (!findings.length) {
        return 'No findings to validate.';
    }

    const proven = findings.filter(finding => getCorroborationLabel(finding) === 'PROVEN').length;
    const corroborated = findings.filter(finding => getCorroborationLabel(finding) === 'CORROBORATED' && (finding.provenance === 'deterministic' || hasIndependentAiReview(finding))).length;
    const safeProbeValidated = findings.filter(finding =>
        finding.provenance !== 'deterministic'
        && finding.safeProbe?.verdict === 'confirmed'
        && !hasIndependentAiReview(finding)
        && getCorroborationLabel(finding) === 'CORROBORATED'
    ).length;
    const finderOnly = findings.filter(finding =>
        finding.provenance !== 'deterministic'
        && !hasIndependentAiReview(finding)
        && finding.safeProbe?.verdict !== 'confirmed'
        && getCorroborationLabel(finding) === 'CORROBORATED'
    ).length;
    const manualReview = findings.filter(finding => needsManualReview(finding)).length;
    const partial = findings.filter(finding => getCorroborationLabel(finding) === 'PARTIAL').length;

    const parts: string[] = [];
    if (proven > 0) {
        parts.push(`${proven} verified`);
    }
    if (corroborated > 0) {
        parts.push(`${corroborated} cross-checked`);
    }
    if (safeProbeValidated > 0) {
        parts.push(`${safeProbeValidated} safe-probe validated`);
    }
    if (finderOnly > 0) {
        parts.push(`${finderOnly} finder-only`);
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
    const risky = findingsByFile
        .map(item => ({
            ...item,
            promotedFindings: item.result.findings.filter(finding => isPromotedFinding(finding, item.file)),
        }))
        .filter(item => item.promotedFindings.length > 0)
        .slice(0, 3);
    if (!risky.length) {
        const hasFindings = findingsByFile.some(item => item.result.findings.length > 0);
        return [
            hasFindings
                ? 'No proof-promoted findings. Review Possible Extra Findings before applying fixes.'
                : 'No immediate action needed from this scan.',
            '',
        ];
    }

    const lines: string[] = [];
    for (const item of risky) {
        const topFinding = [...item.promotedFindings].sort((left, right) => riskRank(right) - riskRank(left))[0];
        const title = topFinding.canonicalTitle || topFinding.title;
        const confidenceSuffix = needsManualReview(topFinding) ? ' Manual review recommended before acting.' : '';
        const remediation = getCanonicalRemediation(topFinding).remediation;
        const proofSuffix = ` Proof: ${getProofStatusDisplayLabel(getFindingProofStatus(topFinding, item.file))}.`;
        lines.push(`- \`${item.file}\` (${item.result.score.toFixed(1)}/10): ${title}. ${remediation}${confidenceSuffix}${proofSuffix}`);
    }
    lines.push('');
    return lines;
}

function buildPossibleExtraFindingLines(
    items: Array<{ file: string; finding: ScanResult['findings'][number]; result?: ScanResult }>,
): string[] {
    const extras = items
        .filter(item => getFindingProofStatus(item.finding, item.file) === 'unproven_extra')
        .sort((left, right) => riskRank(right.finding) - riskRank(left.finding))
        .slice(0, 8);

    if (!extras.length) {
        return [];
    }

    const lines = [
        '## Possible Extra Findings',
        '',
        'These findings are not promoted to Fix First because the engine could not prove the exploit hypothesis or they sit in a helper layer that does not own the security decision.',
        '',
    ];

    for (const item of extras) {
        const peerFindings = extras
            .filter(peer => peer.file === item.file)
            .map(peer => peer.finding);
        const title = getFindingDisplayTitle(item.finding, peerFindings);
        const layer = item.finding.evidenceContract?.responsibilityLayer;
        const reason = isLikelyUnprovenHelperFinding(item.finding, item.file)
            ? 'helper-layer extra'
            : 'missing proof contract';
        const callerPath = item.finding.callerPath
            ? `, caller path: ${item.finding.callerPath.verdict.replace(/_/g, ' ')}`
            : '';
        lines.push(`- \`${item.file}\`: ${title} (${reason}${layer ? `, layer: ${layer}` : ''}${callerPath}).`);
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
    const providerComparisonNotes = getProviderComparisonNotes(snapshot.results);
    const providerDisagreementProofLines = getProviderDisagreementProofLines(root, snapshot.results);
    const engineTelemetry = aggregateEngineTelemetry(snapshot.results);
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
            ...buildFrameworkScopeLines(snapshot.results),
            `- Confidence posture: ${buildConfidencePostureLine(allFindings)}`,
            `- Engine evidence: ${summarizeEngineEvidence(allFindings)}`,
            `- Proof posture: ${summarizeProofPosture(allFindings)}`,
            ...buildEngineTelemetryLines(engineTelemetry),
            `- Design context: ${buildDesignContextLabel(snapshot.results)}`,
            ...buildDesignMapOverviewLines(snapshot.results),
            ...buildDriftOverviewLines(snapshot.results),
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

        lines.push(...buildPossibleExtraFindingLines(sortedFindingItems));

        if (providerComparisonNotes.length) {
            lines.push('## Provider Comparison Notes');
            lines.push('');
            for (const note of providerComparisonNotes) {
                lines.push(`- ${note}`);
            }
            for (const proof of providerDisagreementProofLines) {
                lines.push(`- Proof pass: ${proof}`);
            }
            lines.push('');
        }

        const summaryDriftLines = buildDriftBoxReportLines(snapshot.results);
        if (summaryDriftLines.length) {
            lines.push('## Drift Box');
            lines.push('');
            lines.push(...summaryDriftLines);
            lines.push(...buildDriftRunReportLines(snapshot.results));
            lines.push('');
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
        `- Engine evidence: ${summarizeEngineEvidence(allFindings)}`,
        `- Proof posture: ${summarizeProofPosture(allFindings)}`,
        ...buildEngineTelemetryLines(engineTelemetry),
        `- Design context: ${buildDesignContextLabel(snapshot.results)}`,
        ...buildDesignMapOverviewLines(snapshot.results),
        ...buildDriftOverviewLines(snapshot.results),
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
        `- Engine evidence: ${summarizeEngineEvidence(allFindings)}`,
        `- Proof posture: ${summarizeProofPosture(allFindings)}`,
        ...buildEngineTelemetryLines(engineTelemetry),
        `- Design context: ${buildDesignContextLabel(snapshot.results)}`,
        ...buildDesignMapOverviewLines(snapshot.results),
        ...buildDriftOverviewLines(snapshot.results),
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
        ...buildFrameworkScopeLines(snapshot.results),
        `- Project context: ${buildProjectContextLabel(projectContextSummary)}`,
        ...buildDesignContextReportLines(snapshot.results),
        ...buildDesignMapReportLines(snapshot.results),
        ...buildDriftBoxReportLines(snapshot.results),
        ...buildDriftRunReportLines(snapshot.results),
        `- Errors: ${snapshot.errors.length}`,
        `- Scan warnings: ${warnings.length}`,
        '',
    ];

    if (providerComparisonNotes.length) {
        lines.push('## Provider Comparison Notes', '');
        for (const note of providerComparisonNotes) {
            lines.push(`- ${note}`);
        }
        for (const proof of providerDisagreementProofLines) {
            lines.push(`- Proof pass: ${proof}`);
        }
        lines.push('');
    }

    lines.push(...buildPossibleExtraFindingLines(allFindingItems));

    lines.push('## Findings By File', '');

    if (findingsByFile.length) {
        for (const item of findingsByFile) {
            lines.push(`### ${item.file}`);
            lines.push('');
            lines.push(`- File risk score: ${item.result.score.toFixed(1)}/10`);
            lines.push(`- Findings: ${item.result.findings.length}`);
            const fileAiUsage = getAiUsageSummary(item.result);
            lines.push(`- AI usage: ${fileAiUsage.requestCount} request(s), ${fileAiUsage.totalTokens} token(s)`);
            if (item.result.providerComparisonNotes?.length) {
                lines.push(`- Provider comparison: ${item.result.providerComparisonNotes.join(' | ')}`);
            }
            if (item.result.providerDisagreementProofs?.length) {
                lines.push(`- Provider disagreement proof: ${item.result.providerDisagreementProofs.map(proof => `${proof.verdict}: ${proof.reason}`).join(' | ')}`);
            }
            if (item.result.findings.length) {
                const promotedFindings = item.result.findings.filter(finding => isPromotedFinding(finding, item.file));
                const topFinding = [...promotedFindings].sort((left, right) => riskRank(right) - riskRank(left))[0];
                if (topFinding) {
                    lines.push(`- Fix first: ${topFinding.canonicalTitle || topFinding.title} (${topFinding.riskScore ?? 'n/a'}/10 risk)`);
                    lines.push(`- Why this matters: ${topFinding.explanation || 'No explanation returned.'}`);
                    lines.push(`- What to change: ${getCanonicalRemediation(topFinding).remediation}`);
                } else {
                    lines.push('- Fix first: no proof-promoted finding in this file');
                }
            }
            lines.push(`- Confidence: ${buildConfidencePostureLine(item.result.findings)}`);
            lines.push(`- Engine evidence: ${summarizeEngineEvidence(item.result.findings)}`);
            lines.push(`- Proof posture: ${summarizeProofPosture(item.result.findings, item.file)}`);
            lines.push(...buildEngineTelemetryLines(item.result.engineTelemetry));
            lines.push(`- Design context: ${item.result.designContext ? buildDesignContextLabel([item]) : 'not checked'}`);
            lines.push(`- Manual review: ${item.result.findings.filter(finding => needsManualReview(finding)).length} AI finding(s) needing review`);
            lines.push('');

            if (!item.result.findings.length) {
                lines.push(`- Summary: ${summarizeFileResult(item.result)}`);
                lines.push(`- Coverage: ${hasPartialAiCoverage(item.result) ? 'Partial AI coverage or deterministic-only fallback affected this file' : 'Normal for this file'}`);
                lines.push(`- Project context: ${buildProjectContextLabel(item.result.projectContextSummary && item.result.projectContextSummary !== 'none' ? item.result.projectContextSummary : 'none')}`);
                lines.push(`- Design context: ${item.result.designContext ? buildDesignContextLabel([item]) : 'not checked'}`);
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
            lines.push(`- Engine evidence: ${summarizeEngineEvidence(item.result.findings)}`);
            lines.push(`- Proof posture: ${summarizeProofPosture(item.result.findings, item.file)}`);
            lines.push(...buildEngineTelemetryLines(item.result.engineTelemetry));
            if (!usesAiForFindings(item.result)) {
                lines.push('- AI review: not used for the final finding set in this file');
            }
            lines.push(`- Project context: ${buildProjectContextLabel(item.result.projectContextSummary && item.result.projectContextSummary !== 'none' ? item.result.projectContextSummary : 'none')}`);
            lines.push(`- Design context: ${item.result.designContext ? buildDesignContextLabel([item]) : 'not checked'}`);
            lines.push(`- Knowledge sources: ${buildKnowledgeSourceDetail(item.packContext)}`);
            lines.push('');
            lines.push('| Finding | What drives the score | Evidence confidence |');
            lines.push('| --- | --- | --- |');
            for (const finding of item.result.findings.slice().sort((left, right) => riskRank(right) - riskRank(left))) {
                lines.push(
                    `| ${escapeMarkdown(getFindingDisplayTitle(finding, item.result.findings))} | ${escapeMarkdown(summarizeFindingRow(finding))} | ${escapeMarkdown(formatEvidenceConfidence(finding))} |`,
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
                lines.push(`#### ${getFindingDisplayTitle(finding, item.result.findings)}`);
                lines.push(`- Location: \`${item.file}\` at L${finding.line}${finding.lineEnd !== finding.line ? `-${finding.lineEnd}` : ''}`);
                lines.push(`- Finding risk: ${finding.severity} impact / ${getFindingLikelihood(finding)} likelihood / ${finding.riskScore ?? 'n/a'}/10`);
                lines.push(`- Analysis mode: ${getScanTierDisplayLabel(finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI'))}`);
                lines.push(`- Confidence: ${getConfidenceDisplayLabel(finding.confidenceTier ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'PLAUSIBLE'))}`);
                if (finding.provenance !== 'deterministic') {
                    lines.push(`- AI signal: ${getConfidenceBand(getAiConfidence(finding))}, final ${formatPercent(getAiConfidence(finding))}${needsManualReview(finding) ? ' (manual review recommended)' : ''}`);
                    lines.push(`- AI review path: ${getAiReviewPathLabel(finding)}`);
                    lines.push(`- AI review trace: ${formatAiPassBandSummary(finding)}`);
                }
                lines.push(`- Evidence: ${getEvidenceDisplayLabel(finding)}`);
                if (!finding.evidenceContract) {
                    lines.push(`- Proof status: ${getProofStatusDisplayLabel(getFindingProofStatus(finding, item.file))}`);
                }
                lines.push(...buildEvidenceContractLines(finding, item.file));
                lines.push(...buildSafeProbeLines(finding));
                if (finding.callerPath) {
                    lines.push(`- Caller-path verdict: ${finding.callerPath.verdict.replace(/_/g, ' ')}`);
                    lines.push(`- Caller-path reason: ${finding.callerPath.reason}`);
                    if (finding.callerPath.unsafeCallers?.length) {
                        const unsafe = finding.callerPath.unsafeCallers
                            .slice(0, 3)
                            .map(caller => `\`${caller.file}\` L${caller.line}${caller.functionName ? ` (${caller.functionName})` : ''}`)
                            .join(', ');
                        lines.push(`- Unsafe caller path(s): ${unsafe}`);
                    }
                    for (const caller of finding.callerPath.callers.slice(0, 3)) {
                        const guard = caller.guardKind ? `${caller.guardStatus} (${caller.guardKind})` : caller.guardStatus;
                        lines.push(`  - Caller: \`${caller.file}\` L${caller.line}${caller.functionName ? ` | function ${caller.functionName}` : ''}${caller.via?.length ? ` | via ${caller.via.join(' -> ')}` : ''} | guard ${guard}${caller.sourceSignal ? ` | source ${caller.sourceSignal}` : ''}`);
                    }
                }
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
