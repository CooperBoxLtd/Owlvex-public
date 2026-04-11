/**
 * AC-002: Subject Classification
 *
 * Classifies handler function parameters as SESSION-derived identity or
 * UNTRUSTED caller-supplied identifiers. This is the first layer of the
 * access-control axis — it identifies the subject (who is acting).
 *
 * SESSION parameters: currentUser, user, me, session, authUser, principal
 * UNTRUSTED parameters: any *Id suffix, userId, docId, id, resourceId, requestedId
 * UNKNOWN: db, req, res, and other infrastructure/context params
 */

import fs from 'node:fs/promises';
import { SUBJECT_STATES } from './types.mjs';
import { mergeSubjects, isCallerControlled } from './lattice.mjs';

// Parameters that represent the authenticated session identity.
const SESSION_PARAMS = new Set([
  'currentUser', 'user', 'me', 'session', 'authUser', 'principal', 'identity',
]);

// Parameters that represent infrastructure/context — neither SESSION nor UNTRUSTED.
const INFRA_PARAMS = new Set([
  'db', 'req', 'res', 'next', 'ctx', 'context', 'flag', 'options', 'config',
]);

// Pattern for caller-supplied resource identifiers.
// Matches: userId, docId, id, resourceId, requestedId, postId, any *Id suffix.
const UNTRUSTED_PARAM_PATTERN = /^(id|userId|docId|resourceId|requestedId|postId|commentId|orderId|itemId|.*Id)$/;

function classifyParam(param) {
  if (SESSION_PARAMS.has(param)) return SUBJECT_STATES.SESSION;
  if (INFRA_PARAMS.has(param)) return SUBJECT_STATES.UNKNOWN;
  if (UNTRUSTED_PARAM_PATTERN.test(param)) return SUBJECT_STATES.UNTRUSTED;
  return SUBJECT_STATES.UNKNOWN;
}

function extractHandlerParams(source) {
  const match = source.match(/function\s+handler\s*\(([^)]*)\)/);
  if (!match) {
    throw new Error('Could not find handler function.');
  }

  return match[1]
    .split(',')
    .map((param) => param.trim())
    .filter(Boolean);
}

export async function evaluateFile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const params = extractHandlerParams(source);

  const classifications = params.map((param) => ({
    param,
    classification: classifyParam(param),
  }));

  const subjectSource = classifications.reduce(
    (current, { classification }) => mergeSubjects(current, classification),
    SUBJECT_STATES.UNKNOWN,
  );

  return {
    params: classifications,
    subjectSource,
    finding: isCallerControlled(subjectSource),
  };
}
