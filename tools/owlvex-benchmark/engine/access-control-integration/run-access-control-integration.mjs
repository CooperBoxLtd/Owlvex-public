import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from '../ac001/evaluator.mjs';
import { normalizeAccessControlFinding } from './normalize-finding.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/access_control_integration');
const cases = [
  'idor_direct_positive.js',
  'owned_resource_safe_negative.js',
  'auth_only_insufficient_edge.js',
  'explicit_authz_safe_negative.js',
  'role_check_safe_negative.js',
];

async function readExpected(expectedPath) {
  return JSON.parse(await fs.readFile(expectedPath, 'utf8'));
}

async function main() {
  const results = [];

  for (const name of cases) {
    const jsPath = path.join(corpusDir, name);
    const expectedPath = path.join(corpusDir, name.replace(/\.js$/, '.expected.json'));

    const [expected, rawActual] = await Promise.all([
      readExpected(expectedPath),
      evaluateFile(jsPath),
    ]);

    const actual = normalizeAccessControlFinding(jsPath, rawActual);

    const passed =
      rawActual.finding === expected.finding &&
      rawActual.findingType === expected.finding_type &&
      rawActual.resourceShape === expected.resource_shape &&
      rawActual.policyCheck === expected.policy_check;

    results.push({
      file: name,
      expectedFinding: expected.finding,
      actualFinding: rawActual.finding,
      expectedFindingType: expected.finding_type,
      actualFindingType: rawActual.findingType,
      normalizedFinding: actual,
      passed,
    });
  }

  const passed = results.filter((result) => result.passed).length;
  console.log(JSON.stringify({
    suite: 'access-control-integration',
    passed,
    total: results.length,
    results,
  }, null, 2));

  if (passed !== results.length) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
