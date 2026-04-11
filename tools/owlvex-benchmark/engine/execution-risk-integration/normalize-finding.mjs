import path from 'node:path';

function deriveType(result) {
  if (!result.finding) {
    return 'safe-execution-path';
  }

  if (result.contextValid === false) {
    return 'context-mismatch-execution';
  }

  if (result.sinkKind === 'shell') {
    return 'unsafe-shell-execution';
  }

  return 'unsafe-process-execution';
}

function deriveSeverity(result) {
  if (!result.finding) {
    return 'none';
  }

  return result.sinkKind === 'shell' ? 'high' : 'medium';
}

function buildExplanation(result) {
  if (!result.finding) {
    if (result.transformationAtSink === 'sanitized' && result.contextValid) {
      return 'Input reaches an execution sink through a valid transformation for the sink context.';
    }

    return 'Execution path remains safe under deterministic trust and sink analysis.';
  }

  if (result.contextValid === false) {
    return 'A transformed value reaches an execution sink, but the transformation context does not match the sink context.';
  }

  if (result.sinkKind === 'shell') {
    return 'An unsafe value reaches a shell execution sink in a dangerous usage context.';
  }

  return 'An unsafe value reaches a process execution sink in a dangerous usage context.';
}

export function normalizeExecutionRiskFinding(filePath, result) {
  const baseName = path.basename(filePath, '.js');

  return {
    id: `execution-risk:${baseName}:GR-001`,
    axis: 'execution-risk',
    rule: 'GR-001',
    family: 'injection-execution',
    type: deriveType(result),
    severity: deriveSeverity(result),
    confidence: 1,
    finding: result.finding,
    explanation: buildExplanation(result),
    evidence: {
      file: path.basename(filePath),
      sink: result.sink ?? null,
      sinkKind: result.sinkKind ?? null,
      sinkContext: result.sinkContext ?? null,
      expression: result.expressionAtSink ?? null,
      variable: result.sinkVariable ?? null,
    },
    state: {
      trustState: result.trustStateAtSink ?? 'UNKNOWN',
      transformation: result.transformationAtSink ?? 'none',
      sanitizer: result.sanitizerAtSink ?? null,
      transformationContext: result.transformationContextAtSink ?? null,
      contextValid: result.contextValid ?? true,
      effectiveTrustState: result.effectiveTrustState ?? (result.trustStateAtSink ?? 'UNKNOWN'),
      dangerousInContext: result.dangerousInContext ?? false,
      unsafeAtSink: result.unsafeAtSink ?? false,
    },
    provenance: {
      source: 'deterministic-benchmark',
      pipeline: ['GR-002', 'GR-003', 'GR-004', 'GR-005', 'GR-001'],
    },
  };
}
