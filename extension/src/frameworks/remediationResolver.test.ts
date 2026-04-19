import {
    buildGroundedRemediationPromptContext,
    resolveRemediationForFinding,
} from './remediationResolver';
import { configureRulePackRuntime, resetRulePackRuntime } from './rulePackRegistry';

describe('remediationResolver', () => {
    beforeEach(() => {
        resetRulePackRuntime();
    });

    it('selects framework-specific remediation guidance when a matching variant exists', () => {
        configureRulePackRuntime(
            undefined,
            undefined,
            {
                entries: [{
                    id: 'owlvex.remediation.path_traversal.001',
                    issue_id: 'owlvex.issue.path_traversal.001',
                    title: 'Canonical remediation for path traversal',
                    canonical_fix_summary: 'Use a safe filesystem boundary.',
                    framework_variants: [{
                        framework: 'Express',
                        summary: 'Resolve request-derived filenames against a fixed base path.',
                        recommended_actions: [
                            'Map user choices to known-safe file identifiers.',
                            'Verify the resolved path stays under the storage root.',
                        ],
                    }],
                    validation_steps: ['Replay ../ payloads and confirm rejection.'],
                    unsafe_alternatives: ['Strip ../ tokens without canonical boundary checks.'],
                    references: [{
                        label: 'OWASP Path Traversal',
                        kind: 'official-doc',
                        publisher: 'OWASP',
                    }],
                    provenance: {
                        source_type: 'hybrid',
                        curation_method: 'manual',
                        review_status: 'reviewed',
                        sources: [{ label: 'OWASP Path Traversal', kind: 'official-doc' }],
                    },
                }],
            },
        );

        const remediation = resolveRemediationForFinding({
            id: 'finding-1',
            line: 12,
            lineEnd: 12,
            severity: 'HIGH',
            framework: 'Express',
            ruleCode: 'AC-001',
            title: 'Path traversal',
            explanation: 'User input reaches filesystem APIs.',
            threat: 'Arbitrary file read.',
            fix: 'Normalize input.',
            confidence: 0.9,
            canonicalId: 'owlvex.issue.path_traversal.001',
        });

        expect(remediation.remediation).toBe('Resolve request-derived filenames against a fixed base path.');
        expect(remediation.frameworkVariant?.framework).toBe('Express');
        expect(remediation.recommendedActions).toContain('Map user choices to known-safe file identifiers.');
        expect(remediation.validationSteps).toContain('Replay ../ payloads and confirm rejection.');
        expect(remediation.unsafeAlternatives).toContain('Strip ../ tokens without canonical boundary checks.');
        expect(remediation.cheatSheetGuidance).toEqual([]);
        expect(remediation.modelNote).toBe('Normalize input.');
    });

    it('builds a concise grounded prompt context from loaded remediation entries', () => {
        configureRulePackRuntime(
            undefined,
            undefined,
            {
                entries: [{
                    id: 'owlvex.remediation.sql_injection.001',
                    issue_id: 'owlvex.issue.sql_injection.001',
                    title: 'Canonical remediation for SQL injection',
                    canonical_fix_summary: 'Use parameter binding.',
                    framework_variants: [{
                        framework: 'Express',
                        summary: 'Use placeholders and values arrays.',
                        recommended_actions: ['Replace string SQL with parameterized execution.'],
                    }],
                    validation_steps: ['Replay SQL metacharacter payloads.'],
                    unsafe_alternatives: ['Manual quote escaping.'],
                    references: [{
                        label: 'OWASP SQL Injection Prevention Cheat Sheet',
                        kind: 'cheat-sheet',
                        publisher: 'OWASP',
                    }],
                    provenance: {
                        source_type: 'hybrid',
                        curation_method: 'manual',
                        review_status: 'reviewed',
                        sources: [{ label: 'OWASP SQL Injection Prevention Cheat Sheet', kind: 'cheat-sheet' }],
                    },
                }],
            },
        );

        const context = buildGroundedRemediationPromptContext(['owlvex.issue.sql_injection.001']);
        expect(context).toContain('owlvex.issue.sql_injection.001: Use parameter binding.');
        expect(context).toContain('Frameworks: Express: Use placeholders and values arrays.');
        expect(context).toContain('Cheat sheet guidance: OWASP SQL Injection Prevention Cheat Sheet:');
        expect(context).toContain('Actions: Use prepared statements or ORM-safe bindings.');
        expect(context).toContain('Validate: Replay SQL metacharacter payloads.');
        expect(context).toContain('Avoid: Manual quote escaping.');
    });
});
