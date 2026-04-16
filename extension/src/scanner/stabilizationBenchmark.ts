export interface ParsedReportFile {
    file: string;
    findings: string[];
}

export interface ParsedReport {
    targetLabel?: string;
    files: ParsedReportFile[];
}

export interface FileExpectation {
    file: string;
    expectedState?: 'clean' | 'finding';
    requiredFindings?: string[];
    forbiddenFindings?: string[];
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

        for (let inner = index + 1; inner < lines.length; inner += 1) {
            const line = lines[inner];
            if (/^###\s+/.test(line)) {
                break;
            }

            const tableMatch = line.match(/^\|\s*(.+?)\s*\|\s*impact .+\|\s*(?:AI|Deterministic)/);
            if (tableMatch && tableMatch[1] !== 'Finding') {
                findings.push(tableMatch[1].trim());
            }
        }

        files.push({ file, findings });
    }

    return { targetLabel, files };
}

export function evaluateParsedReport(report: ParsedReport, manifest: BenchmarkManifest): BenchmarkEvaluation {
    const failures: BenchmarkFailure[] = [];
    const byFile = new Map(report.files.map(entry => [normalizeFile(entry.file), entry]));

    for (const expectation of manifest.expectations) {
        const normalizedFile = normalizeFile(expectation.file);
        const reportEntry = byFile.get(normalizedFile);
        const findingTitles = reportEntry?.findings ?? [];

        if (expectation.expectedState === 'clean' && findingTitles.length > 0) {
            failures.push({
                file: expectation.file,
                message: `expected clean but found: ${findingTitles.join(', ')}`,
            });
        }

        if (expectation.expectedState === 'finding' && findingTitles.length === 0) {
            failures.push({
                file: expectation.file,
                message: 'expected at least one finding but none were reported',
            });
        }

        for (const requiredFinding of expectation.requiredFindings ?? []) {
            if (!findingTitles.includes(requiredFinding)) {
                failures.push({
                    file: expectation.file,
                    message: `missing required finding: ${requiredFinding}`,
                });
            }
        }

        for (const forbiddenFinding of expectation.forbiddenFindings ?? []) {
            if (findingTitles.includes(forbiddenFinding)) {
                failures.push({
                    file: expectation.file,
                    message: `forbidden finding present: ${forbiddenFinding}`,
                });
            }
        }
    }

    return {
        passed: failures.length === 0,
        failures,
    };
}

function normalizeFile(value: string): string {
    return value.replace(/\//g, '\\').trim().toLowerCase();
}
