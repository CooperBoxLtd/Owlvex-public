import { SUBJECT_STATES } from './types.mjs';

/**
 * Merge two subject classifications for a handler parameter set.
 * If SESSION and UNTRUSTED identifiers coexist, the result is MIXED.
 */
export function mergeSubjects(a, b) {
  if (a === SUBJECT_STATES.MIXED || b === SUBJECT_STATES.MIXED) return SUBJECT_STATES.MIXED;
  if (a === SUBJECT_STATES.UNKNOWN) return b;
  if (b === SUBJECT_STATES.UNKNOWN) return a;
  if (a === b) return a;
  // SESSION + UNTRUSTED → MIXED
  return SUBJECT_STATES.MIXED;
}

/**
 * Returns true when the subject source contains caller-supplied identifiers
 * that could be manipulated to access another user's resources.
 */
export function isCallerControlled(subjectSource) {
  return subjectSource === SUBJECT_STATES.UNTRUSTED || subjectSource === SUBJECT_STATES.MIXED;
}
