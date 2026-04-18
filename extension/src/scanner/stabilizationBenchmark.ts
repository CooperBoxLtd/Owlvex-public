export interface ParsedReportFile {
    file: string;
    findings: string[];
    detections: string[];
    primaryScanMode?: string;
    scanTierPosture?: string;
    corroborationPosture?: string;
}

export interface ParsedReport {
    targetLabel?: string;
    files: ParsedReportFile[];
}

export interface FileExpectation {
    file: string;
    language?: string;
    family?: string;
    expectedState?: 'clean' | 'finding';
    requiredFindings?: string[];
    forbiddenFindings?: string[];
    requiredDetectionIncludes?: string[];
    requiredPrimaryScanMode?: string;
    requiredScanTierPostureIncludes?: string[];
    requiredCorroborationPostureIncludes?: string[];
}

export interface BenchmarkManifest {
    name: string;
    expectations: FileExpectation[];
}

export interface BenchmarkFailure {
    file: string;
    message: string;
}

export interface BenchmarkEvaluation {
    passed: boolean;
    failures: BenchmarkFailure[];
    metrics: BenchmarkEvaluationMetrics;
}

export interface BenchmarkEvaluationMetrics {
    filesChecked: number;
    expectedFindingFiles: number;
    expectedCleanFiles: number;
    findingFilesSatisfied: number;
    cleanFilesSatisfied: number;
    requiredFindingsChecked: number;
    requiredFindingsSatisfied: number;
    forbiddenFindingsChecked: number;
    forbiddenFindingsSatisfied: number;
    requiredDetectionChecks: number;
    requiredDetectionSatisfied: number;
    primaryScanModesChecked: number;
    primaryScanModesSatisfied: number;
    scanTierPostureChecks: number;
    scanTierPostureSatisfied: number;
    corroborationPostureChecks: number;
    corroborationPostureSatisfied: number;
    totalFailures: number;
}

export function parseMarkdownReport(markdown: string): ParsedReport {
    const lines = markdown.split(/\r?\n/);
    const files: ParsedReportFile[] = [];
    let targetLabel: string | undefined;

    for (const line of lines) {
        const targetMatch = line.match(/^Target:\s+`(.+)`$/);
        if (targetMatch) {
            targetLabel = targetMatch[1];
        }
    }

    for (let index = 0; index < lines.length; index += 1) {
        const headingMatch = lines[index].match(/^###\s+(.+)$/);
        if (!headingMatch) {
            continue;
        }

        const file = headingMatch[1].trim();
        const findings: string[] = [];
        const detections: string[] = [];
        let primaryScanMode: string | undefined;
        let scanTierPosture: string | undefined;
        let corroborationPosture: string | undefined;

        for (let inner = index + 1; inner < lines.length; inner += 1) {
            const line = lines[inner];
            if (/^###\s+/.test(line)) {
                break;
            }

            const primaryScanModeMatch = line.match(/^-\s+(?:Primary scan mode|Analysis mode):\s+(.+)$/);
            if (primaryScanModeMatch && !primaryScanMode) {
                primaryScanMode = primaryScanModeMatch[1].trim();
            }

            const scanTierPostureMatch = line.match(/^-\s+(?:Scan tier posture|Analysis mix):\s+(.+)$/);
            if (scanTierPostureMatch && !scanTierPosture) {
                scanTierPosture = scanTierPostureMatch[1].trim();
            }

            const corroborationPostureMatch = line.match(/^-\s+(?:Corroboration posture|Evidence):\s+(.+)$/);
            if (corroborationPostureMatch && !corroborationPosture) {
                corroborationPosture = corroborationPostureMatch[1].trim();
            }

            const tableMatch = line.match(/^\|\s*(.+?)\s*\|\s*.+\|\s*(.+?)\s*\|$/);
            if (tableMatch && tableMatch[1] !== 'Finding') {
                const findingTitle = tableMatch[1].trim();
                const detection = tableMatch[2].trim();
                if (findingTitle === '---' || detection === '---') {
                    continue;
                }
                findings.push(findingTitle);
                detections.push(detection);
            }
        }

        files.push({ file, findings, detections, primaryScanMode, scanTierPosture, corroborationPosture });
    }

    return { targetLabel, files };
}

export function evaluateParsedReport(report: ParsedReport, manifest: BenchmarkManifest): BenchmarkEvaluation {
    const failures: BenchmarkFailure[] = [];
    const byFile = new Map(report.files.map(entry => [normalizeFile(entry.file), entry]));
    const metrics: BenchmarkEvaluationMetrics = {
        filesChecked: manifest.expectations.length,
        expectedFindingFiles: 0,
        expectedCleanFiles: 0,
        findingFilesSatisfied: 0,
        cleanFilesSatisfied: 0,
        requiredFindingsChecked: 0,
        requiredFindingsSatisfied: 0,
        forbiddenFindingsChecked: 0,
        forbiddenFindingsSatisfied: 0,
        requiredDetectionChecks: 0,
        requiredDetectionSatisfied: 0,
        primaryScanModesChecked: 0,
        primaryScanModesSatisfied: 0,
        scanTierPostureChecks: 0,
        scanTierPostureSatisfied: 0,
        corroborationPostureChecks: 0,
        corroborationPostureSatisfied: 0,
        totalFailures: 0,
    };

    for (const expectation of manifest.expectations) {
        const normalizedFile = normalizeFile(expectation.file);
        const reportEntry = byFile.get(normalizedFile);
        const findingTitles = reportEntry?.findings ?? [];
        const detections = reportEntry?.detections ?? [];
        const primaryScanMode = reportEntry?.primaryScanMode ?? 'none';
        const scanTierPosture = reportEntry?.scanTierPosture ?? 'none';
        const corroborationPosture = reportEntry?.corroborationPosture ?? 'none';
        let fileSatisfied = true;

        if (expectation.expectedState === 'clean' && findingTitles.length > 0) {
            metrics.expectedCleanFiles += 1;
            fileSatisfied = false;
            failures.push({
                file: expectation.file,
                message: `expected clean but found: ${findingTitles.join(', ')}`,
            });
        } else if (expectation.expectedState === 'clean') {
            metrics.expectedCleanFiles += 1;
            metrics.cleanFilesSatisfied += 1;
        }

        if (expectation.expectedState === 'finding' && findingTitles.length === 0) {
            metrics.expectedFindingFiles += 1;
            fileSatisfied = false;
            failures.push({
                file: expectation.file,
                message: 'expected at least one finding but none were reported',
            });
        } else if (expectation.expectedState === 'finding') {
            metrics.expectedFindingFiles += 1;
            metrics.findingFilesSatisfied += 1;
        }

        for (const requiredFinding of expectation.requiredFindings ?? []) {
            metrics.requiredFindingsChecked += 1;
            if (!findingTitles.includes(requiredFinding)) {
                fileSatisfied = false;
                failures.push({
                    file: expectation.file,
                    message: `missing required finding: ${requiredFinding}`,
                });
            } else {
                metrics.requiredFindingsSatisfied += 1;
            }
        }

        for (const forbiddenFinding of expectation.forbiddenFindings ?? []) {
            metrics.forbiddenFindingsChecked += 1;
            if (findingTitles.includes(forbiddenFinding)) {
                fileSatisfied = false;
                failures.push({
                    file: expectation.file,
                    message: `forbidden finding present: ${forbiddenFinding}`,
                });
            } else {
                metrics.forbiddenFindingsSatisfied += 1;
            }
        }

        for (const expected of expectation.requiredDetectionIncludes ?? []) {
            metrics.requiredDetectionChecks += 1;
            if (!detections.some(detection => detection.toLowerCase().includes(expected.toLowerCase()))) {
                fileSatisfied = false;
                failures.push({
                    file: expectation.file,
                    message: `detection summary missing expected fragment: ${expected}`,
                });
            } else {
                metrics.requiredDetectionSatisfied += 1;
            }
        }

        if (expectation.requiredPrimaryScanMode) {
            metrics.primaryScanModesChecked += 1;
            if (primaryScanMode !== expectation.requiredPrimaryScanMode) {
                fileSatisfied = false;
                failures.push({
                    file: expectation.file,
                    message: `expected primary scan mode ${expectation.requiredPrimaryScanMode} but found ${primaryScanMode}`,
                });
            } else {
                metrics.primaryScanModesSatisfied += 1;
            }
        }

        for (const expected of expectation.requiredScanTierPostureIncludes ?? []) {
            metrics.scanTierPostureChecks += 1;
            if (!scanTierPosture.toLowerCase().includes(expected.toLowerCase())) {
                fileSatisfied = false;
                failures.push({
                    file: expectation.file,
                    message: `scan tier posture missing expected fragment: ${expected}`,
                });
            } else {
                metrics.scanTierPostureSatisfied += 1;
            }
        }

        for (const expected of expectation.requiredCorroborationPostureIncludes ?? []) {
            metrics.corroborationPostureChecks += 1;
            if (!corroborationPosture.toLowerCase().includes(expected.toLowerCase())) {
                fileSatisfied = false;
                failures.push({
                    file: expectation.file,
                    message: `corroboration posture missing expected fragment: ${expected}`,
                });
            } else {
                metrics.corroborationPostureSatisfied += 1;
            }
        }

        void fileSatisfied;
    }

    metrics.totalFailures = failures.length;

    return {
        passed: failures.length === 0,
        failures,
        metrics,
    };
}

function normalizeFile(value: string): string {
    return value.replace(/\//g, '\\').trim().toLowerCase();
}
