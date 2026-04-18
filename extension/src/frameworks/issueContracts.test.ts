import { ISSUE_CATALOG, getIssueFamilyDefinition } from './issueCatalog';
import { ISSUE_PROOF_CONTRACTS, PROOF_TRACKED_LANGUAGES, getIssueProofContract } from './issueContracts';

describe('issueContracts', () => {
    it('maps every proof contract to a canonical issue and matching family', () => {
        const issuesById = new Map(ISSUE_CATALOG.map(issue => [issue.id, issue]));

        for (const contract of ISSUE_PROOF_CONTRACTS) {
            const issue = issuesById.get(contract.issueId);
            expect(issue).toBeDefined();
            expect(issue?.family).toBe(contract.familyId);
            expect(getIssueFamilyDefinition(contract.familyId)?.label).toBeTruthy();
        }
    });

    it('keeps deterministic language claims explicit and non-overlapping', () => {
        for (const contract of ISSUE_PROOF_CONTRACTS) {
            expect(contract.supportedDeterministicLanguages.length).toBeGreaterThan(0);
            for (const language of contract.supportedDeterministicLanguages) {
                expect(PROOF_TRACKED_LANGUAGES).toContain(language);
                expect(contract.notClaimedDeterministicLanguages).not.toContain(language);
            }
            for (const language of contract.notClaimedDeterministicLanguages) {
                expect(PROOF_TRACKED_LANGUAGES).toContain(language);
            }
        }
    });

    it('retrieves proof contracts by canonical issue id', () => {
        expect(getIssueProofContract('owlvex.issue.sql_injection.001')?.contractLabel).toBe('SQL Injection');
        expect(getIssueProofContract('owlvex.issue.insecure_deserialization.001')?.supportedDeterministicLanguages).toEqual(
            expect.arrayContaining(['python', 'java']),
        );
    });

    it('records safe pattern expectations for every proof contract', () => {
        expect(
            ISSUE_PROOF_CONTRACTS.every(contract => contract.safePatternExpectations.length > 0 && Boolean(contract.proofBoundary)),
        ).toBe(true);
    });
});
