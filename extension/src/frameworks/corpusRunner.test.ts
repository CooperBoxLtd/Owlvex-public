import path from 'path';

import { evaluateCorpus } from './corpusRunner';

describe('corpusRunner', () => {
    it('evaluates the family-aware corpus and reports grouped metrics', () => {
        const repoRoot = path.resolve(process.cwd(), '..');
        const summary = evaluateCorpus(repoRoot);

        expect(summary.total).toBeGreaterThanOrEqual(20);
        expect(summary.issueAccuracy).toBeGreaterThanOrEqual(0);
        expect(summary.familyAccuracy).toBeGreaterThanOrEqual(summary.issueAccuracy);
        expect(summary.byFamily['Injection & Execution']).toBeDefined();
        expect(summary.byFamily['Secrets & Credential Exposure']).toBeDefined();
    });
});
