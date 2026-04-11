import { ISSUE_CATALOG, ISSUE_FAMILY_CATALOG, getIssueFamilyDefinition, IssueApplicability } from './issueCatalog';

describe('issueCatalog', () => {
    it('contains a materially expanded canonical issue set', () => {
        expect(ISSUE_CATALOG.length).toBeGreaterThanOrEqual(55);
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

    it('assigns detection metadata to every canonical issue', () => {
        expect(
            ISSUE_CATALOG.every(issue => issue.detectionLevel && typeof issue.requiresTrustTracking === 'boolean'),
        ).toBe(true);
    });

    it('assigns applicability to every canonical issue', () => {
        const validApplicabilities: IssueApplicability[] = ['global', 'conditional'];
        expect(
            ISSUE_CATALOG.every(issue => validApplicabilities.includes(issue.applicability)),
        ).toBe(true);
    });

    it('conditional issues declare their required context signals', () => {
        const conditional = ISSUE_CATALOG.filter(issue => issue.applicability === 'conditional');
        expect(conditional.length).toBeGreaterThan(0);
        expect(conditional.every(issue => Array.isArray(issue.requires) && issue.requires.length > 0)).toBe(true);
    });

    it('tenant_isolation_missing is correctly marked as conditional requiring multi_tenant_context', () => {
        const issue = ISSUE_CATALOG.find(i => i.id === 'owlvex.issue.tenant_isolation_missing.001');
        expect(issue).toBeDefined();
        expect(issue!.applicability).toBe('conditional');
        expect(issue!.requires).toContain('multi_tenant_context');
    });

    it('global issues do not declare required context', () => {
        const global = ISSUE_CATALOG.filter(issue => issue.applicability === 'global');
        // Global issues should have no `requires` field (or empty array is acceptable)
        expect(global.every(issue => !issue.requires || issue.requires.length === 0)).toBe(true);
    });
});
