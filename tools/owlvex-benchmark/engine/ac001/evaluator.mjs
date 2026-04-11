/**
 * AC-001: Access Control Final Decision
 *
 * Thin consumer that wraps AC-005 (context validation) and converts the
 * combined resource/policy assessment into a final access-control finding.
 *
 * AC-001 must not reconstruct trust, resource shape, or policy checks from
 * raw source strings. It consumes the AC-005 output exclusively.
 *
 * Finding types:
 *   direct-idor          — ARBITRARY resource + MISSING policy
 *   auth-only-insufficient — ARBITRARY resource + AUTH_ONLY policy
 *   access-control-violation — other contextValid=false combinations
 */

import { evaluateFile as evaluateContextFile } from '../ac005/evaluator.mjs';

function deriveFindingType(resourceShape, policyCheck, contextValid) {
  if (!contextValid && resourceShape === 'ARBITRARY') {
    if (policyCheck === 'MISSING') return 'direct-idor';
    if (policyCheck === 'AUTH_ONLY') return 'auth-only-insufficient';
    return 'access-control-violation';
  }

  return null;
}

export async function evaluateFile(filePath) {
  const contextResult = await evaluateContextFile(filePath);

  const findingType = deriveFindingType(
    contextResult.resourceShape,
    contextResult.policyCheck,
    contextResult.contextValid,
  );

  return {
    ...contextResult,
    finding: contextResult.finding,
    findingType,
  };
}
