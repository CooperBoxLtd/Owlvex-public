import { TRUST_STATES } from './types.mjs';

export function mergeTrust(left, right) {
  if (left === right) {
    return left;
  }

  if (left === TRUST_STATES.UNKNOWN) {
    return right;
  }

  if (right === TRUST_STATES.UNKNOWN) {
    return left;
  }

  if (left === TRUST_STATES.MIXED || right === TRUST_STATES.MIXED) {
    return TRUST_STATES.MIXED;
  }

  return TRUST_STATES.MIXED;
}

export function mergeEnvironments(baseEnv, leftEnv, rightEnv) {
  const names = new Set([
    ...baseEnv.keys(),
    ...leftEnv.keys(),
    ...rightEnv.keys(),
  ]);
  const merged = new Map();

  for (const name of names) {
    const base = baseEnv.get(name) ?? TRUST_STATES.UNKNOWN;
    const left = leftEnv.get(name) ?? base;
    const right = rightEnv.get(name) ?? base;
    merged.set(name, mergeTrust(left, right));
  }

  return merged;
}
