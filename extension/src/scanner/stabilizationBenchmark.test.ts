import { evaluateParsedReport, parseMarkdownReport } from './stabilizationBenchmark';

describe('stabilizationBenchmark', () => {
    it('parses findings by file from markdown reports', () => {
        const report = parseMarkdownReport([
            '# Owlvex Vulnerability Scan Report',
            '',
            'Target: `tools/demo`',
            '',
            '## Findings By File',
            '',
            '### 03-debug-unsafe.js',
            '',
            '| Finding | Score Factors | Detection |',
            '| --- | --- | --- |',
            '| Debug mode or framework error detail enabled in production | tier proven \\| corroboration proven \\| impact medium \\| likelihood medium \\| risk 5/10 | Deterministic `SM-002` |',
            '',
            '### 04-debug-safe.js',
            '',
            '| Finding | Score Factors | Detection |',
            '| --- | --- | --- |',
            '| Debug mode or framework error detail enabled in production | tier plausible \\| corroboration corroborated \\| impact medium \\| likelihood medium \\| risk 5/10 | AI 90% |',
        ].join('\n'));

        expect(report.targetLabel).toBe('tools/demo');
        expect(report.files).toEqual([
            {
                file: '03-debug-unsafe.js',
                findings: ['Debug mode or framework error detail enabled in production'],
            },
            {
                file: '04-debug-safe.js',
                findings: ['Debug mode or framework error detail enabled in production'],
            },
        ]);
    });

    it('evaluates clean and finding expectations against parsed reports', () => {
        const report = parseMarkdownReport([
            '## Findings By File',
            '',
            '### src\\db.js',
            '',
            '| Finding | Score Factors | Detection |',
            '| --- | --- | --- |',
            '| Unsanitized SQL query construction | tier plausible \\| corroboration corroborated \\| impact critical \\| likelihood high \\| risk 10/10 | AI 62% |',
            '| Broken Access Control in getDocumentById | tier plausible \\| corroboration corroborated \\| impact high \\| likelihood high \\| risk 9/10 | AI 80% |',
            '',
            '### src\\server.js',
            '',
            '| Finding | Score Factors | Detection |',
            '| --- | --- | --- |',
            '| Missing CSRF protection on state-changing request | tier plausible \\| corroboration partial \\| impact medium \\| likelihood medium \\| risk 5/10 | AI 80% |',
        ].join('\n'));

        const evaluation = evaluateParsedReport(report, {
            name: 'demo-app',
            expectations: [
                {
                    file: 'src\\db.js',
                    requiredFindings: [
                        'Unsanitized SQL query construction',
                        'Broken Access Control in getDocumentById',
                    ],
                    forbiddenFindings: ['Sensitive data exposed in logs'],
                },
                {
                    file: 'src\\server.js',
                    expectedState: 'clean',
                },
                {
                    file: 'src\\lib\\tokens.js',
                    expectedState: 'finding',
                },
            ],
        });

        expect(evaluation.passed).toBe(false);
        expect(evaluation.failures).toEqual([
            {
                file: 'src\\server.js',
                message: 'expected clean but found: Missing CSRF protection on state-changing request',
            },
            {
                file: 'src\\lib\\tokens.js',
                message: 'expected at least one finding but none were reported',
            },
        ]);
        expect(evaluation.metrics).toEqual({
            filesChecked: 3,
            expectedFindingFiles: 1,
            expectedCleanFiles: 1,
            findingFilesSatisfied: 0,
            cleanFilesSatisfied: 0,
            requiredFindingsChecked: 2,
            requiredFindingsSatisfied: 2,
            forbiddenFindingsChecked: 1,
            forbiddenFindingsSatisfied: 1,
            totalFailures: 2,
        });
    });
});
