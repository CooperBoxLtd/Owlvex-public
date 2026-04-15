import fs from 'node:fs/promises';
import path from 'node:path';
import { repoRoot } from './repo-root.mjs';

const latestPath = path.resolve(
  repoRoot,
  'tools/owlvex-benchmark/runs/ai-evals/latest.json',
);

function buildStatus(summary) {
  const totalCases = summary.totalCases ?? 0;
  const passedCases = summary.passedCases ?? 0;
  const failedCases = Array.isArray(summary.failedCases) ? summary.failedCases : [];
  const passRate = totalCases > 0 ? Number(((passedCases / totalCases) * 100).toFixed(1)) : 0;

  const confidence =
    passRate >= 90 ? 'good-directional-signal'
      : passRate >= 75 ? 'usable-with-review'
        : 'not-stable-enough';

  const releaseStatement =
    confidence === 'good-directional-signal'
      ? 'AI eval lane is behaving consistently on the covered AI-only cases. Treat this as a directional quality signal, not deterministic proof.'
      : confidence === 'usable-with-review'
        ? 'AI eval lane is partially consistent on the covered AI-only cases. Review failures before using it as a strong quality signal.'
        : 'AI eval lane is not stable enough on the covered AI-only cases. Do not treat this as a reliable quality signal yet.';

  return {
    overall: {
      confidence,
      releaseStatement,
      reasons: [
        `cases passing: ${passedCases}/${totalCases}`,
        `pass rate: ${passRate}%`,
        `failed cases: ${failedCases.length ? failedCases.join(', ') : 'none'}`,
        `model: ${summary.run?.model ?? 'unknown'}`,
      ],
    },
  };
}

async function main() {
  const raw = await fs.readFile(latestPath, 'utf8');
  const summary = JSON.parse(raw);
  const status = buildStatus(summary);

  console.log(JSON.stringify({
    generatedAt: summary.generatedAt,
    summary,
    status,
  }, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
