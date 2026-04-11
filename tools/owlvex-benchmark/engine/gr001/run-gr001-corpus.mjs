import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { normalizeExecutionRiskFinding } from '../execution-risk-integration/normalize-finding.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/injection_execution');

async function readExpected(expectedPath) {
  const raw = await fs.readFile(expectedPath, 'utf8');
  return JSON.parse(raw);
}

async function listCorpusCases() {
  const entries = await fs.readdir(corpusDir);
  return entries
    .filter((name) => name.endsWith('.js'))
    .sort()
    .map((name) => ({
      jsPath: path.join(corpusDir, name),
      expectedPath: path.join(corpusDir, name.replace(/\.js$/, '.expected.json')),
    }));
}

function compareCase(actual, expected) {
  return {
    sink: actual.sink,
    expectedTrustState: expected.trust_state,
    actualTrustState: actual.trustStateAtSink,
    expectedUnsafeAtSink: expected.unsafe_at_sink,
    actualUnsafeAtSink: actual.unsafeAtSink,
    expectedFinding: expected.finding,
    actualFinding: actual.finding,
    passed:
      actual.sink === expected.sink &&
      actual.trustStateAtSink === expected.trust_state &&
      actual.unsafeAtSink === expected.unsafe_at_sink &&
      actual.finding === expected.finding,
  };
}

async function main() {
  const cases = await listCorpusCases();
  const results = [];

  for (const corpusCase of cases) {
    const [expected, actual] = await Promise.all([
      readExpected(corpusCase.expectedPath),
      evaluateFile(corpusCase.jsPath),
    ]);

    results.push({
      file: path.basename(corpusCase.jsPath),
      normalizedFinding: normalizeExecutionRiskFinding(corpusCase.jsPath, actual),
      ...compareCase(actual, expected),
    });
  }

  const passed = results.filter((result) => result.passed).length;
  console.log(JSON.stringify({
    suite: 'gr001-injection-execution',
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
