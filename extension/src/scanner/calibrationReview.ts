import type { Finding, ScanResult } from './scanEngine';

export interface StoredScanRecord {
    scanId: string;
    result: ScanResult;
    targetLabel?: string;
    scannedAt?: string;
}

function getFindingLikelihood(finding: Finding): 'LOW' | 'MEDIUM' | 'HIGH' {
    const normalized = String(finding.likelihood ?? 'MEDIUM').toUpperCase();
    return normalized === 'LOW' || normalized === 'HIGH' || normalized === 'MEDIUM'
        ? normalized
        : 'MEDIUM';
}

function riskRank(finding: Finding): number {
    const severityRank = finding.severity === 'CRITICAL'
        ? 4
        : finding.severity === 'HIGH'
        ? 3
        : finding.severity === 'MEDIUM'
        ? 2
        : 1;
    return (finding.riskScore ?? 0) * 10 + severityRank;
}

function summarizeIssueFamilies(findings: Finding[]): string {
    const labels = [...new Set(
        findings
            .map(item => item.canonicalFamilyLabel || item.canonicalFamily)
            .filter((value): value is string => Boolean(value))
    )];

    return labels.length ? labels.join(', ') : 'Unresolved';
}

function buildScoreBreakdown(findings: Finding[]): string {
    if (!findings.length) {
        return 'No penalties were applied, so the file kept the full 10.0 baseline.';
    }

    const penalties = findings.map(finding => {
        const basePenalty = finding.severity === 'CRITICAL'
            ? 4
            : finding.severity === 'HIGH'
            ? 2.5
            : finding.severity === 'MEDIUM'
            ? 1.5
            : 0.5;
        const multiplier = getFindingLikelihood(finding) === 'HIGH'
            ? 1.5
            : getFindingLikelihood(finding) === 'LOW'
            ? 0.75
            : 1;
        return `${finding.severity.toLowerCase()} x ${getFindingLikelihood(finding).toLowerCase()} (-${Number((basePenalty * multiplier).toFixed(2))})`;
    });

    return `Started at 10.0, then applied penalties from ${penalties.join(', ')}.`;
}

function buildScoreMeaning(result: ScanResult): string | undefined {
    const topRisk = getTopRiskFinding(result.findings);
    if (!topRisk) {
        return undefined;
    }

    return `${result.score.toFixed(1)}/10 is the overall target score after penalties, while ${topRisk.riskScore ?? 'n/a'}/10 is the highest single-finding risk.`;
}

function formatTarget(record: StoredScanRecord): string {
    return record.targetLabel?.trim() || record.scanId;
}

function formatScannedAt(record: StoredScanRecord): string {
    if (!record.scannedAt) {
        return 'n/a';
    }

    const timestamp = new Date(record.scannedAt);
    return Number.isNaN(timestamp.getTime()) ? record.scannedAt : timestamp.toISOString();
}

function getTopRiskFinding(findings: Finding[]): Finding | undefined {
    return findings
        .slice()
        .sort((left, right) => riskRank(right) - riskRank(left))[0];
}

export function buildRiskCalibrationReport(records: StoredScanRecord[]): string {
    const ordered = records
        .slice()
        .sort((left, right) => {
            const leftTime = left.scannedAt ? new Date(left.scannedAt).getTime() : 0;
            const rightTime = right.scannedAt ? new Date(right.scannedAt).getTime() : 0;
            return rightTime - leftTime;
        });
    const averageScore = ordered.length
        ? ordered.reduce((total, item) => total + item.result.score, 0) / ordered.length
        : 0;
    const totalFindings = ordered.reduce((total, item) => total + item.result.findings.length, 0);

    const lines: string[] = [
        '# Owlvex Risk Calibration Review',
        '',
        `Generated: ${new Date().toISOString()}`,
        `Scans reviewed: ${ordered.length}`,
        `Average score: ${averageScore.toFixed(1)}/10`,
        `Total findings across reviewed scans: ${totalFindings}`,
        '',
        '## How To Use',
        '',
        '- Start with the lowest scores and the highest contextual risks.',
        '- Ask whether the score drop feels too soft, too harsh, or about right for the code shown.',
        '- If something feels wrong, change one lever at a time: deterministic likelihood, impact penalty, likelihood multiplier, or a single risk-matrix cell.',
        '- Turn accepted calibration calls into regression tests so the posture stays stable.',
        '',
        '## Review Queue',
        '',
        '| Target | Score | Findings | Top risk | Families |',
        '| --- | ---: | ---: | --- | --- |',
        ...ordered.map(record => {
            const topRisk = getTopRiskFinding(record.result.findings);
            const topRiskLabel = topRisk
                ? `${topRisk.title} (${topRisk.severity}/${getFindingLikelihood(topRisk)} -> ${topRisk.riskScore ?? 'n/a'}/10)`
                : 'None';
            return `| \`${formatTarget(record)}\` | ${record.result.score.toFixed(1)} | ${record.result.findings.length} | ${topRiskLabel} | ${summarizeIssueFamilies(record.result.findings)} |`;
        }),
        '',
        '## Detailed Review',
        '',
    ];

    for (const record of ordered) {
        const result = record.result;
        const topRisk = getTopRiskFinding(result.findings);
        const topFindings = result.findings
            .slice()
            .sort((left, right) => riskRank(right) - riskRank(left))
            .slice(0, 3);

        lines.push(`### ${formatTarget(record)}`);
        lines.push('');
        lines.push(`- Scan ID: \`${record.scanId}\``);
        lines.push(`- Scanned at: ${formatScannedAt(record)}`);
        lines.push(`- Provider/model: ${result.provider} / ${result.model}`);
        lines.push(`- Score: ${result.score.toFixed(1)}/10`);
        lines.push(`- Score drivers: ${buildScoreBreakdown(result.findings)}`);
        lines.push(`- Score meaning: ${buildScoreMeaning(result) ?? 'No findings, so the overall score stayed at the baseline.'}`);
        lines.push(`- Findings: ${result.findings.length}`);
        lines.push(`- Families: ${summarizeIssueFamilies(result.findings)}`);
        lines.push(topRisk
            ? `- Highest contextual risk: ${topRisk.title} | impact ${topRisk.severity} | likelihood ${getFindingLikelihood(topRisk)} | risk ${topRisk.riskScore ?? 'n/a'}/10`
            : '- Highest contextual risk: none');
        lines.push('- Calibration questions:');
        lines.push('Does the score drop match the likely exploitability of the top risk in this target?');
        lines.push('Would you raise or lower likelihood based on concrete code evidence, not deployment guesses?');
        lines.push('Is the highest-risk issue appropriately harsher than the rest of the findings in this target?');
        lines.push('');

        if (!topFindings.length) {
            lines.push('_No findings in this scan._');
            lines.push('');
            continue;
        }

        lines.push('| Finding | Impact | Likelihood | Risk | Why likely |');
        lines.push('| --- | --- | --- | ---: | --- |');
        for (const finding of topFindings) {
            lines.push(
                `| ${finding.title} | ${finding.severity} | ${getFindingLikelihood(finding)} | ${finding.riskScore ?? 'n/a'} | ${finding.likelihoodReasons?.join(' ; ') || 'No contextual reasons recorded'} |`
            );
        }
        lines.push('');
    }

    return lines.join('\n');
}
