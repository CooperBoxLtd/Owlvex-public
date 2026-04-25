import { DeterministicScanner } from './deterministicScanner';

const scanner = new DeterministicScanner();

interface EvidenceCase {
    name: string;
    language: string;
    source: string;
    expectedCanonicalIds: string[];
    expectedEvidenceTypes?: string[];
}

const cases: EvidenceCase[] = [
    {
        name: 'unsafe JS path traversal has source-flow-sink-guard evidence',
        language: 'javascript',
        source: `
const path = require('path');
const fs = require('fs');
function exportReport(req, res) {
  const filePath = path.join('/srv/app/exports', req.query.file);
  const report = fs.readFileSync(filePath, 'utf8');
  res.type('text/plain').send(report);
}`,
        expectedCanonicalIds: ['owlvex.issue.path_traversal.001'],
        expectedEvidenceTypes: ['path-traversal'],
    },
    {
        name: 'safe JS path traversal fix remains clean',
        language: 'javascript',
        source: `
const path = require('path');
const fs = require('fs');
const exportsDir = path.resolve('/srv/app/exports');
function resolveExportPath(requested) {
  if (typeof requested !== 'string' || requested.length === 0) return null;
  if (path.basename(requested) !== requested || path.extname(requested) !== '.txt') return null;
  const resolved = path.resolve(exportsDir, requested);
  const relative = path.relative(exportsDir, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return null;
  return resolved;
}
function exportReport(req, res) {
  const filePath = resolveExportPath(req.query.file);
  if (!filePath) return res.status(400).json({ error: 'invalid_export' });
  const report = fs.readFileSync(filePath, 'utf8');
  res.type('text/plain').send(report);
}`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe client-controlled filter has source-flow-sink-guard evidence',
        language: 'javascript',
        source: `
function matchesFilter(user, filter) {
  return Object.entries(filter).every(([key, value]) => user[key] === value);
}
router.post('/users/search-unsafe', requireAdmin, (req, res) => {
  const filter = req.body && typeof req.body.filter === 'object' && req.body.filter !== null ? req.body.filter : {};
  const results = fakeUsers.filter(user => matchesFilter(user, filter));
  res.json({ count: results.length, results });
});`,
        expectedCanonicalIds: ['owlvex.issue.nosql_injection.001'],
        expectedEvidenceTypes: ['client-controlled-query-filter'],
    },
    {
        name: 'server-built user filter remains clean',
        language: 'javascript',
        source: `
router.post('/users/search-safe', requireAdmin, (req, res) => {
  const filter = {};
  if (typeof req.body.email === 'string') filter.email = req.body.email;
  if (typeof req.body.role === 'string' && ['user', 'admin'].includes(req.body.role)) filter.role = req.body.role;
  const results = fakeUsers.filter(user => matchesFilter(user, filter));
  res.json({ count: results.length, results });
});`,
        expectedCanonicalIds: [],
    },
];

describe('Engine evidence regression gate', () => {
    it.each(cases)('$name', testCase => {
        const findings = scanner.scan(testCase.source, testCase.language);
        expect(findings.map(finding => finding.canonicalId).sort()).toEqual(testCase.expectedCanonicalIds.sort());

        if (testCase.expectedEvidenceTypes?.length) {
            expect(findings.map(finding => finding.evidenceContract?.issueType).sort()).toEqual(testCase.expectedEvidenceTypes.sort());
            for (const finding of findings) {
                expect(finding.evidenceContract).toMatchObject({
                    verdict: 'confirmed',
                    guard: {
                        status: 'missing',
                    },
                });
                expect(finding.evidenceContract?.source?.expression).toBeTruthy();
                expect(finding.evidenceContract?.sink?.expression).toBeTruthy();
                expect(finding.evidenceContract?.rationale).toBeTruthy();
            }
        }
    });
});
