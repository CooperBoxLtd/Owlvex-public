import { formatFrameworkLabel, formatFrameworkSummary, getFrameworkDefinition } from './catalog';

describe('framework catalog', () => {
    it('returns the curated definition for OWASP', () => {
        const framework = getFrameworkDefinition('OWASP');
        expect(framework?.name).toBe('OWASP Top 10');
        expect(framework?.version).toBe('2021');
    });

    it('formats individual framework labels with versions', () => {
        expect(formatFrameworkLabel('STRIDE')).toBe('STRIDE 2026.1');
    });

    it('formats multi-framework summaries cleanly', () => {
        expect(formatFrameworkSummary(['OWASP', 'STRIDE'])).toBe('OWASP 2021, STRIDE 2026.1');
    });

    it('falls back to raw codes for unknown frameworks', () => {
        expect(formatFrameworkSummary(['CUSTOMFW'])).toBe('CUSTOMFW');
    });
});
