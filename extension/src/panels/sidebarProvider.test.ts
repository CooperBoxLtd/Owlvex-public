import { SidebarProvider } from './sidebarProvider';
import { configureRulePackRuntime, resetRulePackRuntime } from '../frameworks/rulePackRegistry';

describe('SidebarProvider', () => {
    beforeEach(() => {
        resetRulePackRuntime();
    });

    it('surfaces remediation detail nodes for grounded findings', () => {
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
                        summary: 'Resolve user paths against a fixed base directory.',
                        recommended_actions: [
                            'Map user choices to identifiers.',
                            'Verify the resolved path stays under the storage root.',
                        ],
                    }],
                    validation_steps: ['Replay ../ payloads and confirm rejection.'],
                    unsafe_alternatives: ['Strip ../ without canonical checks.'],
                    references: [{
                        label: 'OWASP Path Traversal',
                        kind: 'official-doc',
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

        const provider = new SidebarProvider();
        provider.refresh({
            scanId: 'scan-1',
            score: 4.2,
            summary: 'Path traversal found.',
            findings: [{
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
                provenance: 'deterministic',
            }],
            positives: [],
            metrics: { critical: 0, high: 1, medium: 0, low: 0 },
            durationMs: 12,
            model: 'test-model',
            provider: 'test-provider',
            warnings: [],
            packContext: {
                mode: 'fresh',
                packIds: ['owlvex.remediation-pack.v1'],
                fetchedAt: '2026-04-14T00:00:00.000Z',
            },
        });

        const roots = provider.getChildren();
        const severityNode = roots.find(item => item.kind === 'severity');
        expect(severityNode).toBeTruthy();

        const findingNode = provider.getChildren(severityNode)[0];
        expect(findingNode.collapsibleState).toBe(1);

        const detailNodes = provider.getChildren(findingNode);
        expect(detailNodes.map(node => node.label)).toEqual(expect.arrayContaining([
            'Fix: Resolve user paths against a fixed base directory.',
            'Validate: Replay ../ payloads and confirm rejection.',
            'Avoid: Strip ../ without canonical checks.',
            'Sources: OWASP Path Traversal',
        ]));
    });
});
