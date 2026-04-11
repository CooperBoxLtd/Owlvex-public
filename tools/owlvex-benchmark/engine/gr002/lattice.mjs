import { EXECUTION_UNSAFE_STATES, TRUST_STATES } from './types.mjs';

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

  if (
    (left === TRUST_STATES.SAFE && right === TRUST_STATES.UNSAFE) ||
    (left === TRUST_STATES.UNSAFE && right === TRUST_STATES.SAFE)
  ) {
    return TRUST_STATES.MIXED;
  }

  return TRUST_STATES.MIXED;
}

export function mergeEnvironments(baseEnv, leftEnv, rightEnv) {
  const merged = new Map();
  const names = new Set([
    ...baseEnv.keys(),
    ...leftEnv.keys(),
    ...rightEnv.keys(),
  ]);

  for (const name of names) {
    const left = leftEnv.has(name) ? leftEnv.get(name) : baseEnv.get(name) ?? TRUST_STATES.UNKNOWN;
    const right = rightEnv.has(name) ? rightEnv.get(name) : baseEnv.get(name) ?? TRUST_STATES.UNKNOWN;
    merged.set(name, mergeTrust(left, right));
  }

  return merged;
}

export function isUnsafeAtSink(state) {
  return EXECUTION_UNSAFE_STATES.has(state);
}
