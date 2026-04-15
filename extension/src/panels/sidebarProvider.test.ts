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
                confidenceTier: 'PROVEN',
                likelihood: 'HIGH',
                likelihoodReasons: ['User-controlled path reaches a filesystem boundary directly.'],
                riskScore: 8,
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
        expect(roots[0].label).toBe('Score: 4.2/10');
        expect(String(roots[0].tooltip)).toContain('Coverage posture: normal');
        expect(String(roots[0].tooltip)).toContain('Top risk: Path traversal | HIGH/HIGH | 8/10');
        const severityNode = roots.find(item => item.kind === 'severity');
        expect(severityNode).toBeTruthy();
        expect(severityNode?.label).toBe('Impact HIGH (1)');

        const findingNode = provider.getChildren(severityNode)[0];
        expect(findingNode.collapsibleState).toBe(1);
        expect(findingNode.label).toBe('L12 Path traversal (8/10)');
        expect(String(findingNode.tooltip)).toContain('[Deterministic] User input reaches filesystem APIs.');

        const detailNodes = provider.getChildren(findingNode);
        expect(detailNodes.map(node => node.label)).toEqual(expect.arrayContaining([
            'Discuss this finding',
            'Review fix',
            'Risk: HIGH/HIGH -> 8/10',
            'Confidence tier: PROVEN',
            'Why likely: User-controlled path reaches a filesystem boundary directly.',
            'Fix: Resolve user paths against a fixed base directory.',
            'Validate: Replay ../ payloads and confirm rejection.',
            'Avoid: Strip ../ without canonical checks.',
            'Sources: OWASP Path Traversal',
        ]));
        const discussNode = detailNodes.find(node => node.label === 'Discuss this finding');
        expect(discussNode?.command?.command).toBe('owlvex.discussFinding');
        expect(discussNode?.command?.arguments?.[0]).toMatchObject({ id: 'finding-1', title: 'Path traversal' });
        const fixPreviewNode = detailNodes.find(node => node.label === 'Review fix');
        expect(fixPreviewNode?.command?.command).toBe('owlvex.generateFixPreview');
        expect(fixPreviewNode?.command?.arguments?.[0]).toMatchObject({ id: 'finding-1', title: 'Path traversal' });
    });

    it('shows AI confidence for AI findings', () => {
        const provider = new SidebarProvider();
        provider.refresh({
            scanId: 'scan-2',
            score: 6.4,
            summary: 'AI issue found.',
            findings: [{
                id: 'finding-ai-1',
                line: 9,
                lineEnd: 9,
                severity: 'MEDIUM',
                framework: 'OWASP',
                ruleCode: 'OWASP-A03',
                title: 'SQL Injection',
                explanation: 'Dynamic SQL is built from user input.',
                threat: 'Data exposure.',
                fix: 'Use parameterized queries.',
                confidence: 0.91,
                provenance: 'ai',
                confidenceTier: 'PLAUSIBLE',
                likelihood: 'HIGH',
                riskScore: 7,
            }],
            positives: [],
            metrics: { critical: 0, high: 0, medium: 1, low: 0 },
            durationMs: 20,
            model: 'test-model',
            provider: 'test-provider',
            warnings: [],
        } as any);

        const severityNode = provider.getChildren().find(item => item.kind === 'severity');
        const findingNode = provider.getChildren(severityNode)[0];
        expect(String(findingNode.tooltip)).toContain('[AI 91%] Dynamic SQL is built from user input.');

        const detailNodes = provider.getChildren(findingNode);
        expect(detailNodes.map(node => node.label)).toContain('AI confidence: 91%');
        expect(detailNodes.map(node => node.label)).toContain('Confidence tier: PLAUSIBLE');
    });

    it('surfaces partial coverage posture when warnings indicate degraded AI coverage', () => {
        const provider = new SidebarProvider();
        provider.refresh({
            scanId: 'scan-3',
            score: 10,
            summary: 'No findings detected.',
            findings: [],
            positives: [],
            metrics: { critical: 0, high: 0, medium: 0, low: 0 },
            durationMs: 0,
            model: 'test-model',
            provider: 'test-provider',
            warnings: ['AI coverage intentionally paused for the rest of this repo scan after repeated provider 429 warnings. Owlvex returned deterministic-only results for this file.'],
        } as any);

        const roots = provider.getChildren();
        expect(String(roots[0].tooltip)).toContain('Coverage posture: partial AI coverage or deterministic-only fallback');
    });
});
