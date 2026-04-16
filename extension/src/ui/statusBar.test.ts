import * as vscode from 'vscode';
import { StatusBar } from './statusBar';

describe('StatusBar', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('shows AI confidence in the top-risk tooltip for AI findings', () => {
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
            }],
        } as any);

        const item = (vscode.window.createStatusBarItem as jest.Mock).mock.results[0].value;
        expect(item.tooltip).toContain('File risk score: 6.7/10');
        expect(item.tooltip).toContain('Fix first: SQL Injection | HIGH/HIGH | 9/10 | AI 93%');
    });
});
