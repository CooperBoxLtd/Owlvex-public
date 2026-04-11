/**
 * AC-005: Context Validation
 *
 * Validates whether the authorization policy (AC-003) is adequate for the
 * resource access pattern (AC-004). This is the context layer of the
 * access-control axis — it determines whether the combination is safe.
 *
 * Context rules:
 *   OWNED / CONSTANT resource   → contextValid = true  (session-scoped, inherently safe)
 *   ARBITRARY + EXPLICIT        → contextValid = true  (explicit permission check)
 *   ARBITRARY + OWNERSHIP       → contextValid = true  (ownership comparison present)
 *   ARBITRARY + ROLE            → contextValid = true  (role-based policy present)
 *   ARBITRARY + AUTH_ONLY       → contextValid = false (authentication ≠ authorization)
 *   ARBITRARY + MISSING         → contextValid = false (no policy at all)
 *   UNKNOWN resource            → contextValid = true  (insufficient information to flag)
 */

import { evaluateFile as evaluateResourceFile } from '../ac004/evaluator.mjs';
import { evaluateFile as evaluatePolicyFile } from '../ac003/evaluator.mjs';

function isContextValid(resourceShape, policyCheck) {
  if (resourceShape === 'OWNED' || resourceShape === 'CONSTANT' || resourceShape === 'UNKNOWN') {
    return true;
  }

  // resourceShape === 'ARBITRARY'
  if (policyCheck === 'EXPLICIT' || policyCheck === 'OWNERSHIP' || policyCheck === 'ROLE') {
    return true;
  }

  // AUTH_ONLY or MISSING — insufficient for arbitrary resource access.
  return false;
}

export async function evaluateFile(filePath) {
  const [resourceResult, policyResult] = await Promise.all([
    evaluateResourceFile(filePath),
    evaluatePolicyFile(filePath),
  ]);

  const contextValid = isContextValid(resourceResult.resourceShape, policyResult.policyCheck);
  const effectiveRisk = !contextValid ? 'IDOR' : 'NONE';

  return {
    resourceShape: resourceResult.resourceShape,
    policyCheck: policyResult.policyCheck,
    contextValid,
    effectiveRisk,
    finding: !contextValid,
  };
}
