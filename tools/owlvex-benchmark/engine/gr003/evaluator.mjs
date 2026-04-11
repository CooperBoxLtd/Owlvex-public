import { evaluateFile as evaluateTrustFile } from '../gr002/evaluator.mjs';
import { isUnsafeAtSink } from '../gr002/lattice.mjs';

export async function evaluateFile(filePath) {
  const trustResult = await evaluateTrustFile(filePath);
  const primaryFinding = trustResult.primaryFinding;

  return {
    ...trustResult,
    sink: primaryFinding?.sink ?? null,
    trustStateAtSink: primaryFinding?.trustState ?? 'UNKNOWN',
    transformationAtSink: primaryFinding?.transformation ?? 'none',
    finding: primaryFinding ? isUnsafeAtSink(primaryFinding.trustState) : false,
  };
}
