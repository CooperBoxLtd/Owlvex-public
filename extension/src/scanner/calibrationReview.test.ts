import { buildRiskCalibrationReport } from './calibrationReview';
import type { ScanResult } from './scanEngine';

describe('buildRiskCalibrationReport', () => {
    function buildResult(overrides: Partial<ScanResult> = {}): ScanResult {
        return {
            scanId: 'scan-1',
            score: 7.8,
            summary: '1 finding(s) detected.',
            findings: [
                {
                    id: 'f-1',
                    line: 10,
                    lineEnd: 10,
                    severity: 'MEDIUM',
                    framework: 'OWASP',
                    ruleCode: 'SM-001',
                    title: 'Insecure Cookie: httpOnly Flag Missing',
                    explanation: 'Cookie is missing httpOnly.',
                    threat: 'Session theft',
                    fix: 'Set httpOnly.',
                    confidence: 1,
                    provenance: 'deterministic',
                    canonicalFamily: 'AUTH',
                    canonicalFamilyLabel: 'Identity & Auth Failures',
                    likelihood: 'HIGH',
                    likelihoodReasons: ['Cookie name suggests session or auth state'],
                    riskScore: 7,
                },
            ],
            positives: [],
            metrics: { critical: 0, high: 0, medium: 1, low: 0 },
            durationMs: 12,
            model: 'owlvex-gpt4o',
            provider: 'openai',
            warnings: [],
            ...overrides,
        };
    }

    it('renders a calibration queue and detailed review content', () => {
        const report = buildRiskCalibrationReport([
            {
                scanId: 'scan-1',
                targetLabel: 'tools/demo/10-cookie-unsafe.js',
                scannedAt: '2026-04-14T21:00:00.000Z',
                result: buildResult(),
            },
        ]);

        expect(report).toContain('# Owlvex Risk Calibration Review');
        expect(report).toContain('| `tools/demo/10-cookie-unsafe.js` | 7.8 | 1 | Insecure Cookie: httpOnly Flag Missing (MEDIUM/HIGH -> 7/10) | Identity & Auth Failures |');
        expect(report).toContain('- Score breakdown: 10.0 baseline - medium x high (2.25)');
        expect(report).toContain('| Insecure Cookie: httpOnly Flag Missing | MEDIUM | HIGH | 7 | Cookie name suggests session or auth state |');
    });
});
