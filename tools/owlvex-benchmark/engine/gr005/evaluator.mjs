import { isUnsafeAtSink } from '../gr002/lattice.mjs';
import { TRUST_STATES } from '../gr002/types.mjs';
import { evaluateFile as evaluateTrustFile } from '../gr002/evaluator.mjs';
import { evaluateFile as evaluateSinkFile } from '../gr004/evaluator.mjs';

function deriveSinkContext(sinkKind) {
  return sinkKind === 'shell' ? 'shell' : 'generic';
}

function isContextValid(transformation, transformationContext, sinkContext) {
  if (transformation !== 'sanitized') {
    return true;
  }

  if (!transformationContext) {
    return false;
  }

  return transformationContext === 'generic' || transformationContext === sinkContext;
}

function findTrustFindingAtSink(trustResult, sinkResult) {
  if (Array.isArray(trustResult.findings) && trustResult.findings.length > 0) {
    if (sinkResult.variable) {
      for (let index = trustResult.findings.length - 1; index >= 0; index -= 1) {
        const finding = trustResult.findings[index];
        if (finding.sink === sinkResult.sink && finding.variable === sinkResult.variable) {
          return finding;
        }
      }
    }

    if (sinkResult.expression) {
      for (let index = trustResult.findings.length - 1; index >= 0; index -= 1) {
        const finding = trustResult.findings[index];
        if (finding.sink === sinkResult.sink && finding.expression === sinkResult.expression) {
          return finding;
        }
      }
    }
  }

  if (sinkResult.variable) {
    return {
      sink: sinkResult.sink,
      expression: sinkResult.expression,
      variable: sinkResult.variable,
      trustState: trustResult.states[sinkResult.variable] ?? TRUST_STATES.UNKNOWN,
      transformation: trustResult.transformationMetadata?.[sinkResult.variable]?.transformation ?? 'none',
      sanitizer: trustResult.transformationMetadata?.[sinkResult.variable]?.sanitizer ?? null,
      transformationContext: trustResult.transformationMetadata?.[sinkResult.variable]?.context ?? null,
    };
  }

  return trustResult.primaryFinding ?? null;
}

export async function evaluateFile(filePath) {
  const [trustResult, sinkResult] = await Promise.all([
    evaluateTrustFile(filePath),
    evaluateSinkFile(filePath),
  ]);

  if (!sinkResult.sink) {
    return {
      ...trustResult,
      sink: null,
      sinkContext: null,
      contextValid: true,
      effectiveTrustState: TRUST_STATES.UNKNOWN,
      finding: false,
    };
  }

  const trustFinding = findTrustFindingAtSink(trustResult, sinkResult);
  const trustStateAtSink = trustFinding?.trustState ?? TRUST_STATES.UNKNOWN;
  const transformationAtSink = trustFinding?.transformation ?? 'none';
  const sanitizerAtSink = trustFinding?.sanitizer ?? null;
  const transformationContext = trustFinding?.transformationContext ?? null;
  const sinkContext = deriveSinkContext(sinkResult.sinkKind);
  const contextValid = isContextValid(transformationAtSink, transformationContext, sinkContext);
  const effectiveTrustState = trustStateAtSink === TRUST_STATES.SAFE && !contextValid
    ? TRUST_STATES.UNSAFE
    : trustStateAtSink;
  const unsafeAtSink = isUnsafeAtSink(effectiveTrustState);

  return {
    ...trustResult,
    sink: sinkResult.sink,
    sinkKind: sinkResult.sinkKind,
    sinkContext,
    sinkVariable: sinkResult.variable,
    trustStateAtSink,
    transformationAtSink,
    sanitizerAtSink,
    transformationContextAtSink: transformationContext,
    contextValid,
    effectiveTrustState,
    unsafeAtSink,
    dangerousInContext: sinkResult.dangerousInContext,
    finding: sinkResult.dangerousInContext && unsafeAtSink,
  };
}
