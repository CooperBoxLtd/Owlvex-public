import fs from 'fs';
import path from 'path';

import { ISSUE_CATALOG, getIssueFamilyDefinition } from './issueCatalog';

type CorpusCase = {
    file: string;
    expectedCanonical: string[];
    expectedFamily: string | null;
    expectedFamilies?: string[];
    difficulty?: 'easy' | 'medium' | 'hard';
};

type CorpusManifest = {
    schema_version: string;
    title: string;
    version: string;
    cases: CorpusCase[];
};

describe('golden corpus manifest', () => {
    const repoRoot = path.resolve(process.cwd(), '..');
    const corpusRoot = path.join(repoRoot, 'corpus');
    const manifestPath = path.join(corpusRoot, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as CorpusManifest;
    const knownIssueIds = new Set(ISSUE_CATALOG.map(issue => issue.id));

    it('uses the expected schema and a meaningful corpus size', () => {
        expect(manifest.schema_version).toBe('owlvex.corpus.v1');
        expect(manifest.cases.length).toBeGreaterThanOrEqual(30);
    });

    it('points every manifest entry at a real corpus file', () => {
        expect(
            manifest.cases.every(testCase => fs.existsSync(path.join(corpusRoot, testCase.file))),
        ).toBe(true);
    });

    it('only references known canonical issues and issue families', () => {
        for (const testCase of manifest.cases) {
            expect(testCase.expectedCanonical.every(issueId => knownIssueIds.has(issueId))).toBe(true);
            if (testCase.expectedFamily) {
                expect(getIssueFamilyDefinition(testCase.expectedFamily)?.label).toBeTruthy();
            }
            for (const familyId of testCase.expectedFamilies ?? []) {
                expect(getIssueFamilyDefinition(familyId)?.label).toBeTruthy();
            }
            expect(['easy', 'medium', 'hard']).toContain(testCase.difficulty ?? 'easy');
        }
    });
});
