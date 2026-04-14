import { getCanonicalIssueById, resolveIssue } from './issueResolver';
import { configureRulePackRuntime, resetRulePackRuntime } from './rulePackRegistry';

describe('issueResolver', () => {
    beforeEach(() => {
        resetRulePackRuntime();
    });

    it('resolves exact CWE matches deterministically', () => {
        const resolved = resolveIssue({
            title: 'Unsafe shell execution',
            explanation: 'User input reaches exec and allows arbitrary commands.',
            threat: 'Arbitrary command execution.',
            fix: 'Use spawn with fixed arguments.',
            framework: 'OWASP',
            ruleCode: 'CWE-78',
            severity: 'CRITICAL',
        });

        expect(resolved?.issue.id).toBe('owlvex.issue.command_injection.001');
        expect(resolved?.matchedSignals).toContain('CWE:CWE-78');
    });

    it('resolves keyword-based findings when no canonical code is returned', () => {
        const resolved = resolveIssue({
            title: 'SQL Injection',
            explanation: 'Raw SQL query is built from username input.',
            threat: 'Attackers can dump database contents.',
            fix: 'Use parameterized queries.',
            framework: 'OWASP',
            ruleCode: '',
            severity: 'HIGH',
        });

        expect(resolved?.issue.id).toBe('owlvex.issue.sql_injection.001');
        expect(resolved?.matchedSignals).toEqual(expect.arrayContaining(['sql injection', 'query', 'parameterized']));
    });

    it('returns undefined for unrelated findings', () => {
        const resolved = resolveIssue({
            title: 'Minor style issue',
            explanation: 'Variable name should be shorter.',
            threat: '',
            fix: 'Rename the variable.',
            framework: 'CLEANCODE',
            ruleCode: '',
            severity: 'LOW',
        });

        expect(resolved).toBeUndefined();
    });

    it('exposes canonical issue lookup by id', () => {
        expect(getCanonicalIssueById('owlvex.issue.hardcoded_secret.001')?.title).toBe('Hardcoded secret in source code');
    });

    it('exposes detection metadata for new direct Phase A issues', () => {
        const issue = getCanonicalIssueById('owlvex.issue.code_injection.eval.001');
        expect(issue?.detectionLevel).toBe('direct');
        expect(issue?.requiresTrustTracking).toBe(true);
    });

    it('prefers specific secret subtypes over generic hardcoded secret matches', () => {
        const resolved = resolveIssue({
            title: 'Hardcoded API key',
            explanation: 'The code contains an apiKey constant with a real-looking API key.',
            threat: 'An attacker can use the API key directly.',
            fix: 'Move the API key to process.env.API_KEY.',
            framework: 'CWE',
            ruleCode: 'CWE-798',
            severity: 'HIGH',
        });

        expect(resolved?.issue.id).toBe('owlvex.issue.hardcoded_api_key.001');
    });

    it('does not classify a hardcoded admin username as a secret', () => {
        const resolved = resolveIssue({
            title: 'Hardcoded admin user',
            explanation: 'A hardcoded username value is present: ops-admin.',
            threat: 'May reveal naming conventions.',
            fix: 'Move ADMIN_USER to configuration.',
            framework: 'CWE',
            ruleCode: 'CWE-798',
            severity: 'LOW',
        });

        expect(resolved).toBeUndefined();
    });

    it('prefers verified dynamic mapping packs for exact framework-id matches', () => {
        configureRulePackRuntime(
            {
                issues: [{
                    id: 'owlvex.issue.sql_injection.001',
                    slug: 'sql-injection-unsanitized-query-construction',
                    title: 'SQL injection from verified pack',
                    category: 'injection',
                    family: 'family.injection_execution',
                    severity: 'high',
                    stride: ['Tampering'],
                    mappings: { cwe: ['CWE-89'] },
                    detection: { patterns: ['sql injection'] },
                    remediation: { summary: 'Use parameterized queries.' },
                }],
            },
            {
                mappings: [{
                    issue_id: 'owlvex.issue.sql_injection.001',
                    framework_mappings: [{
                        framework_code: 'CWE',
                        external_id: 'CWE-89',
                    }],
                }],
            },
        );

        const resolved = resolveIssue({
            title: 'Database injection',
            explanation: 'The tool returned a framework mapping only.',
            threat: 'Data exposure',
            fix: 'Parameterize the query.',
            framework: 'CWE',
            ruleCode: 'CWE-89',
            severity: 'HIGH',
        });

        expect(resolved?.issue.title).toBe('SQL injection from verified pack');
        expect(resolved?.confidence).toBe(0.99);
        expect(resolved?.matchedSignals).toEqual(['CWE:CWE-89']);
    });

    it('uses cached pack issue metadata for canonical issue lookups', () => {
        configureRulePackRuntime(
            {
                issues: [{
                    id: 'owlvex.issue.command_injection.001',
                    slug: 'command-injection-unsafe-shell-execution',
                    title: 'Unsafe shell command execution from pack',
                    category: 'injection',
                    family: 'family.injection_execution',
                    severity: 'critical',
                    stride: ['Tampering', 'Denial of Service'],
                    mappings: { cwe: ['CWE-78'] },
                    detection: { patterns: ['command injection', 'shell'] },
                    remediation: { summary: 'Avoid shell invocation.' },
                }],
            },
            undefined,
        );

        expect(getCanonicalIssueById('owlvex.issue.command_injection.001')?.title).toBe('Unsafe shell command execution from pack');
    });
});
