import assert from 'assert';
import { evaluateParsedReport, parseMarkdownReport } from './evaluate-stabilization-report.mjs';

const manifest = {
  expectations: [
    {
      file: 'src\\store\\repositories.js',
      forbidProofPromotedFindings: true,
    },
  ],
};

function evaluate(markdown) {
  return evaluateParsedReport(parseMarkdownReport(markdown), manifest);
}

const unpromotedHelperReport = `
# Owlvex Vulnerability Scan Report

Target: \`tools/benchmark-app\`

## Findings By File

### src/store/repositories.js

- Findings: 2
- Fix first: no proof-promoted finding in this file
- Proof posture: static proven: 0 | AI plausible: 0 | counter-evidence: 0 | unproven extras: 2

#### Missing audit trail for role change
- Proof status: Unproven extra

#### Missing audit trail for account profile change
- Proof status: Unproven extra
`;

const promotedByPostureReport = `
# Owlvex Vulnerability Scan Report

Target: \`tools/benchmark-app\`

## Findings By File

### src/store/repositories.js

- Findings: 1
- Proof posture: static proven: 0 | AI plausible: 1 | counter-evidence: 0 | unproven extras: 0

#### Repository authorization risk
- Proof status: AI plausible with source/sink/guard evidence
`;

const promotedByFindingStatusReport = `
# Owlvex Vulnerability Scan Report

Target: \`tools/benchmark-app\`

## Findings By File

### src/store/repositories.js

- Findings: 1
- Proof posture: static proven: 0 | AI plausible: 0 | counter-evidence: 0 | unproven extras: 1

#### Repository authorization risk
- Proof status: Static proven
`;

const unpromoted = evaluate(unpromotedHelperReport);
assert.equal(unpromoted.passed, true, `zero-count proof labels should not fail helper promotion checks: ${unpromoted.failures.join('; ')}`);
assert.equal(unpromoted.metrics.proofPromotionSatisfied, 1);

const promotedByPosture = evaluate(promotedByPostureReport);
assert.equal(promotedByPosture.passed, false, 'non-zero AI plausible posture should fail helper promotion checks');
assert.deepEqual(promotedByPosture.failures, ['src\\store\\repositories.js: helper-layer finding was proof-promoted']);

const promotedByFindingStatus = evaluate(promotedByFindingStatusReport);
assert.equal(promotedByFindingStatus.passed, false, 'finding-level static proof should fail helper promotion checks');
assert.deepEqual(promotedByFindingStatus.failures, ['src\\store\\repositories.js: helper-layer finding was proof-promoted']);

console.log('stabilization evaluator tests passed');
