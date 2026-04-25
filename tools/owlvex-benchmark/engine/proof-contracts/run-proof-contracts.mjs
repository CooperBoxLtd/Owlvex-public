import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';

import { repoRoot } from '../../repo-root.mjs';

const require = createRequire(import.meta.url);
const { DeterministicScanner } = require('../../../../extension/out/scanner/deterministicScanner.js');

const casesPath = path.resolve(repoRoot, 'tools/owlvex-benchmark/engine/proof-contracts/proof-contract-cases.json');
const runsDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/runs/proof-contracts');

function sorted(values) {
  return [...values].sort();
}

function sameSet(actual, expected) {
  return JSON.stringify(sorted(actual)) === JSON.stringify(sorted(expected));
}

function summarizeEvidence(finding) {
  const contract = finding.evidenceContract;
  if (!contract) {
    return null;
  }

  return {
    issueType: contract.issueType,
    verdict: contract.verdict,
    guardStatus: contract.guard?.status ?? null,
    hasSource: Boolean(contract.source?.expression),
    hasSink: Boolean(contract.sink?.expression),
    hasRationale: Boolean(contract.rationale),
  };
}

function evaluateCase(scanner, testCase) {
  const findings = scanner.scan(testCase.source, testCase.language);
  const actualCanonicalIds = findings.map((finding) => finding.canonicalId);
  const expectedCanonicalIds = testCase.expectedCanonicalIds ?? [];
  const canonicalIdsPass = sameSet(actualCanonicalIds, expectedCanonicalIds);

  const actualEvidenceTypes = findings
    .map((finding) => finding.evidenceContract?.issueType)
    .filter(Boolean);
  const expectedEvidenceTypes = testCase.expectedEvidenceTypes ?? [];
  const evidenceTypesPass = sameSet(actualEvidenceTypes, expectedEvidenceTypes);

  const evidenceShapePass = expectedEvidenceTypes.length === 0 || findings.every((finding) => {
    const contract = finding.evidenceContract;
    return Boolean(
      contract &&
      contract.verdict === 'confirmed' &&
      contract.guard?.status === 'missing' &&
      contract.source?.expression &&
      contract.sink?.expression &&
      contract.rationale,
    );
  });

  return {
    name: testCase.name,
    language: testCase.language,
    expectedCanonicalIds,
    actualCanonicalIds: sorted(actualCanonicalIds),
    expectedEvidenceTypes,
    actualEvidenceTypes: sorted(actualEvidenceTypes),
    evidence: findings.map(summarizeEvidence),
    passed: canonicalIdsPass && evidenceTypesPass && evidenceShapePass,
    canonicalIdsPass,
    evidenceTypesPass,
    evidenceShapePass,
  };
}

function toTimestamp(date) {
  return date.toISOString().replace(/[:.]/g, '-');
}

async function writeArtifacts(summary) {
  await fs.mkdir(runsDir, { recursive: true });
  const timestamp = toTimestamp(new Date(summary.generatedAt));
  const body = `${JSON.stringify(summary, null, 2)}\n`;
  await Promise.all([
    fs.writeFile(path.join(runsDir, 'latest.json'), body, 'utf8'),
    fs.writeFile(path.join(runsDir, `${timestamp}.json`), body, 'utf8'),
  ]);
}

async function main() {
  const cases = JSON.parse(await fs.readFile(casesPath, 'utf8'));
  const scanner = new DeterministicScanner();
  const results = cases.map((testCase) => evaluateCase(scanner, testCase));
  const passed = results.filter((result) => result.passed).length;
  const summary = {
    suite: 'engine-proof-contracts',
    generatedAt: new Date().toISOString(),
    passed,
    total: results.length,
    results,
  };

  await writeArtifacts(summary);
  console.log(JSON.stringify(summary, null, 2));

  if (passed !== results.length) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
