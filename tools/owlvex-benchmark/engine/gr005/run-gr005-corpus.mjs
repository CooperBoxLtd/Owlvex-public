import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/context_mismatch');

async function readExpected(expectedPath) {
  return JSON.parse(await fs.readFile(expectedPath, 'utf8'));
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
    expectedSink: expected.sink,
    actualSink: actual.sink,
    expectedTrustState: expected.trust_state,
    actualTrustState: actual.trustStateAtSink,
    expectedTransformation: expected.transformation,
    actualTransformation: actual.transformationAtSink,
    expectedSanitizer: expected.sanitizer,
    actualSanitizer: actual.sanitizerAtSink,
    expectedTransformationContext: expected.transformation_context,
    actualTransformationContext: actual.transformationContextAtSink,
    expectedSinkContext: expected.sink_context,
    actualSinkContext: actual.sinkContext,
    expectedContextValid: expected.context_valid,
    actualContextValid: actual.contextValid,
    expectedEffectiveTrustState: expected.effective_trust_state,
    actualEffectiveTrustState: actual.effectiveTrustState,
    expectedFinding: expected.finding,
    actualFinding: actual.finding,
    passed:
      actual.sink === expected.sink &&
      actual.trustStateAtSink === expected.trust_state &&
      actual.transformationAtSink === expected.transformation &&
      actual.sanitizerAtSink === expected.sanitizer &&
      actual.transformationContextAtSink === expected.transformation_context &&
      actual.sinkContext === expected.sink_context &&
      actual.contextValid === expected.context_valid &&
      actual.effectiveTrustState === expected.effective_trust_state &&
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
      ...compareCase(actual, expected),
    });
  }

  const passed = results.filter((result) => result.passed).length;
  console.log(JSON.stringify({
    suite: 'gr005-context-mismatch',
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
