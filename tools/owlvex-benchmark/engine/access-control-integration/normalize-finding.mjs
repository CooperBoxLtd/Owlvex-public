/**
 * Normalize an AC-001 result into the canonical deterministic finding shape.
 * Mirrors normalize-finding.mjs in execution-risk-integration and sql-query-integration.
 */

export function normalizeAccessControlFinding(filePath, result) {
  if (!result.finding) {
    return {
      id: null,
      axis: 'access-control',
      rule: null,
      family: 'access-control',
      type: null,
      severity: null,
      confidence: 1,
      evidence: {
        resourceShape: result.resourceShape,
        policyCheck: result.policyCheck,
        contextValid: result.contextValid,
        effectiveRisk: result.effectiveRisk,
      },
      state: {
        finding: false,
        findingType: null,
      },
      provenance: 'deterministic',
    };
  }

  const ruleMap = {
    'direct-idor': 'AC-001',
    'auth-only-insufficient': 'AC-001',
    'access-control-violation': 'AC-001',
  };

  const severityMap = {
    'direct-idor': 'HIGH',
    'auth-only-insufficient': 'MEDIUM',
    'access-control-violation': 'HIGH',
  };

  return {
    id: `ac001:${result.findingType}`,
    axis: 'access-control',
    rule: ruleMap[result.findingType] ?? 'AC-001',
    family: 'access-control',
    type: result.findingType,
    severity: severityMap[result.findingType] ?? 'HIGH',
    confidence: 1,
    evidence: {
      resourceShape: result.resourceShape,
      policyCheck: result.policyCheck,
      contextValid: result.contextValid,
      effectiveRisk: result.effectiveRisk,
    },
    state: {
      finding: true,
      findingType: result.findingType,
    },
    provenance: 'deterministic',
  };
}
