import { evaluateFile as evaluateSinkFile } from '../sq004/evaluator.mjs';
import { evaluateFile as evaluateTransformFile } from '../sq003/evaluator.mjs';
import { TRUST_STATES } from '../sq002/types.mjs';
import { evaluateFile as evaluateTrustFile } from '../sq002/evaluator.mjs';

// SQL context validation rule.
// A transformation context is valid for SQL when no transformation is applied
// (trust propagation handles the risk directly) or when parameterized binding is used.
// HTML escaping and generic sanitizers protect against different attack classes
// and do not constitute a valid transformation context for SQL.
function isContextValidForSql(transformation) {
  if (transformation === 'none') return true;
  if (transformation === 'parameterized') return true;
  return false;
}

function deriveSinkContext(sinkKind) {
  return sinkKind === 'sql' ? 'sql' : 'generic';
}

export async function evaluateFile(filePath) {
  const [sinkResult, transformResult, trustResult] = await Promise.all([
    evaluateSinkFile(filePath),
    evaluateTransformFile(filePath),
    evaluateTrustFile(filePath),
  ]);

  if (!sinkResult.sink) {
    return {
      sink: null,
      sinkContext: null,
      transformation: transformResult.transformation,
      contextValid: true,
      effectiveTrustState: TRUST_STATES.UNKNOWN,
      finding: false,
      explanation: 'No SQL query sink detected.',
    };
  }

  const sinkContext = deriveSinkContext(sinkResult.sinkKind);
  const transformation = transformResult.transformation;
  const contextValid = isContextValidForSql(transformation);

  // For parameterized queries the effective trust state is SAFE regardless of input trust.
  // For all other cases, a non-valid context overrides trust to UNSAFE.
  let effectiveTrustState;
  if (sinkResult.parameterized) {
    effectiveTrustState = TRUST_STATES.SAFE;
  } else if (!contextValid) {
    effectiveTrustState = TRUST_STATES.UNSAFE;
  } else {
    // No transformation case — trust state passes through from trust propagation.
    effectiveTrustState = trustResult.trustStateAtSink ?? TRUST_STATES.UNKNOWN;
  }

  const finding = effectiveTrustState === TRUST_STATES.UNSAFE ||
    effectiveTrustState === TRUST_STATES.MIXED;

  return {
    sink: sinkResult.sink,
    sinkKind: sinkResult.sinkKind,
    sinkContext,
    transformation,
    sqlSafe: transformResult.sqlSafe,
    contextValid,
    effectiveTrustState,
    finding,
    explanation: finding
      ? `Transformation '${transformation}' is not valid for SQL context.`
      : `SQL context is safe — ${transformation === 'parameterized' ? 'parameterized binding' : 'no unsafe data flows'}.`,
  };
}
