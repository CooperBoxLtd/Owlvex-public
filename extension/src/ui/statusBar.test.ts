import * as vscode from 'vscode';
import { StatusBar } from './statusBar';

describe('StatusBar', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('shows qualitative evidence confidence before raw AI audit trace', () => {
        const bar = new StatusBar();
        bar.showResult({
            score: 6.7,
            model: 'test-model',
            packContext: undefined,
            findings: [{
                id: 'finding-1',
                line: 7,
                lineEnd: 7,
                severity: 'HIGH',
                framework: 'OWASP',
                ruleCode: 'OWASP-A03',
                title: 'SQL Injection',
                explanation: 'User input reaches a query sink.',
                threat: 'Data exposure.',
                fix: 'Use parameterized queries.',
                confidence: 0.93,
                provenance: 'ai',
                likelihood: 'HIGH',
                riskScore: 9,
                confidenceTier: 'PLAUSIBLE',
                corroboration: 'UNVERIFIED',
            }],
        } as any);

        const item = (vscode.window.createStatusBarItem as jest.Mock).mock.results[0].value;
        expect(item.tooltip).toContain('File risk score: 6.7/10');
        expect(item.tooltip).toContain('Engine evidence: Structured contracts: 0/1 | confirmed: 0 | missing guards: 0 | deterministic gaps: 0 | AI without contract: 1');
        expect(item.tooltip).toContain('Fix first: SQL Injection | HIGH/HIGH | 9/10 | Evidence: Needs manual review | AI signal 93% audit trace');
    });

    it('shows static proof for deterministic findings instead of numeric confidence', () => {
        const bar = new StatusBar();
        bar.showResult({
            score: 8.4,
            model: 'deterministic',
            packContext: undefined,
            findings: [{
                id: 'finding-1',
                line: 7,
                lineEnd: 7,
                severity: 'HIGH',
                framework: 'OWASP',
                ruleCode: 'PT-001',
                title: 'Path Traversal',
                explanation: 'User input reaches a filesystem sink.',
                threat: 'File disclosure.',
                fix: 'Resolve and boundary-check the path.',
                confidence: 1,
                provenance: 'deterministic',
                likelihood: 'HIGH',
                riskScore: 9,
                confidenceTier: 'PROVEN',
                corroboration: 'PROVEN',
                evidenceContract: {
                    issueType: 'path-traversal',
                    verdict: 'confirmed',
                    source: { kind: 'source', label: 'Request-controlled path segment', expression: 'req.query.file', line: 7 },
                    flow: [{ kind: 'path-construction', label: 'Path construction', expression: 'path.join(base, req.query.file)', line: 7 }],
                    sink: { kind: 'sink', label: 'Filesystem sink', expression: 'fs.readFileSync(filePath)', line: 8 },
                    guard: {
                        status: 'missing',
                        label: 'Base-directory containment guard',
                        reason: 'No recognized containment check is visible.',
                    },
                    rationale: 'Request-controlled input reaches a filesystem sink.',
                },
            }],
        } as any);

        const item = (vscode.window.createStatusBarItem as jest.Mock).mock.results[0].value;
        expect(item.tooltip).toContain('Engine evidence: Structured contracts: 1/1 | confirmed: 1 | missing guards: 1 | deterministic gaps: 0 | AI without contract: 0');
        expect(item.tooltip).toContain('Fix first: Path Traversal | HIGH/HIGH | 9/10 | Evidence: Static proof');
        expect(item.tooltip).not.toContain('100%');
    });
});
