import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/sink_execution');

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
    expectedSinkKind: expected.sink_kind,
    actualSinkKind: actual.sinkKind,
    expectedArgumentIndex: expected.argument_index,
    actualArgumentIndex: actual.argumentIndex,
    expectedDangerousInContext: expected.dangerous_in_context,
    actualDangerousInContext: actual.dangerousInContext,
    expectedExpression: expected.expression,
    actualExpression: actual.expression,
    passed:
      actual.sink === expected.sink &&
      actual.sinkKind === expected.sink_kind &&
      actual.argumentIndex === expected.argument_index &&
      actual.dangerousInContext === expected.dangerous_in_context &&
      actual.expression === expected.expression,
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
    suite: 'gr004-sink-execution',
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
