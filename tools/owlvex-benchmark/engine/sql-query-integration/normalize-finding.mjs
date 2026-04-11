import path from 'node:path';

function deriveType(result) {
  if (!result.finding) {
    return 'safe-sql-path';
  }

  if (result.type === 'context-mismatch-query') {
    return 'context-mismatch-sql';
  }

  if (result.type === 'wrapped-sql-sink') {
    return 'wrapped-sql-injection';
  }

  if (result.type === 'mixed-query-trust') {
    return 'mixed-trust-sql-injection';
  }

  return 'sql-injection';
}

function deriveSeverity(result) {
  return result.finding ? 'high' : 'none';
}

function buildExplanation(result) {
  if (!result.finding) {
    if (result.type === 'parameterized-query') {
      return 'SQL query uses parameterized binding. User input is bound via parameters, not interpolated into query text.';
    }

    return 'SQL path remains safe under deterministic trust and sink analysis.';
  }

  if (result.type === 'context-mismatch-query') {
    return 'A transformation was applied but is not valid for SQL context. HTML-oriented or generic sanitizers do not prevent SQL injection.';
  }

  if (result.type === 'wrapped-sql-sink') {
    return 'A wrapped SQL sink receives interpolated query text containing unsafe user input.';
  }

  if (result.type === 'mixed-query-trust') {
    return 'Branch-dependent user input reaches an interpolated SQL query. At least one code path exposes the sink to unsafe data.';
  }

  return 'User-controlled input is interpolated directly into SQL query text without parameterized binding.';
}

export function normalizeSqlQueryFinding(filePath, result) {
  const baseName = path.basename(filePath, '.js');

  return {
    id: `sql-query:${baseName}:SQ-001`,
    axis: 'sql-query',
    rule: 'SQ-001',
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
      queryExpression: result.queryExpression ?? null,
      parameterized: result.parameterized ?? false,
    },
    state: {
      trustStateAtSink: result.trustStateAtSink ?? 'UNKNOWN',
      transformation: result.transformation ?? result.transformationAtSink ?? 'none',
      contextValid: result.contextValid ?? true,
      effectiveTrustState: result.effectiveTrustState ?? result.trustStateAtSink ?? 'UNKNOWN',
    },
    provenance: {
      source: 'deterministic-benchmark',
      pipeline: ['SQ-002', 'SQ-003', 'SQ-004', 'SQ-005', 'SQ-001'],
    },
  };
}
