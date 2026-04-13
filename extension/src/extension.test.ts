import { normalizeComparisonDiff } from './extension';

describe('normalizeComparisonDiff', () => {
    it('keeps the current backend contract unchanged', () => {
        const diff = normalizeComparisonDiff({
            new_findings: 2,
            resolved_findings: 1,
            new_finding_details: [{ line: 10 }],
            resolved_finding_details: [{ line: 5 }],
        });

        expect(diff.new_findings).toBe(2);
        expect(diff.resolved_findings).toBe(1);
        expect(diff.new_finding_details).toHaveLength(1);
        expect(diff.resolved_finding_details).toHaveLength(1);
    });

    it('normalizes older array-shaped payloads into count and details fields', () => {
        const diff = normalizeComparisonDiff({
            new_findings: [{ line: 10 }, { line: 20 }],
            resolved_findings: [{ line: 5 }],
        });

        expect(diff.new_findings).toBe(2);
        expect(diff.resolved_findings).toBe(1);
        expect(diff.new_finding_details).toEqual([{ line: 10 }, { line: 20 }]);
        expect(diff.resolved_finding_details).toEqual([{ line: 5 }]);
    });
});
