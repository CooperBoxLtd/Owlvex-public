import { ISSUE_CATALOG, ISSUE_FAMILY_CATALOG, getIssueFamilyDefinition } from './issueCatalog';

describe('issueCatalog', () => {
    it('contains a materially expanded canonical issue set', () => {
        expect(ISSUE_CATALOG.length).toBeGreaterThanOrEqual(25);
    });

    it('includes secret subtypes for more precise hardcoded secret matching', () => {
        const ids = ISSUE_CATALOG.map(issue => issue.id);
        expect(ids).toEqual(expect.arrayContaining([
            'owlvex.issue.hardcoded_api_key.001',
            'owlvex.issue.hardcoded_password.001',
            'owlvex.issue.hardcoded_token.001',
        ]));
    });

    it('defines issue families for product-facing grouping', () => {
        expect(ISSUE_FAMILY_CATALOG.map(item => item.label)).toEqual(expect.arrayContaining([
            'Secrets & Credential Exposure',
            'Injection & Execution',
            'Identity & Auth Failures',
        ]));
        expect(
            ISSUE_CATALOG.every(issue => issue.family && getIssueFamilyDefinition(issue.family)?.label),
        ).toBe(true);
    });
});
