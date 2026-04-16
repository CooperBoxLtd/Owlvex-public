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
            score: 8,
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
                scanTier: 'STATIC',
                confidenceTier: 'PROVEN',
                corroboration: 'PROVEN',
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
            projectContextSummary: 'inline project contract',
            packContext: {
                mode: 'fresh',
                packIds: ['owlvex.remediation-pack.v1'],
                fetchedAt: '2026-04-14T00:00:00.000Z',
            },
        });

        const roots = provider.getChildren();
        expect(roots[0].label).toBe('File risk: 8.0/10');
        expect(String(roots[0].tooltip)).toContain('Coverage posture: normal');
        expect(String(roots[0].tooltip)).toContain('Scan tier posture: static: 1');
        expect(String(roots[0].tooltip)).toContain('Corroboration posture: proven: 1');
        expect(String(roots[0].tooltip)).toContain('Project context: inline project contract');
        expect(String(roots[0].tooltip)).toContain('Fix first: Path traversal | HIGH/HIGH | 8/10');
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
            'Fix code',
            'Risk: HIGH/HIGH -> 8/10',
            'Scan tier: STATIC',
            'Confidence tier: PROVEN',
            'Corroboration: PROVEN',
            'Why likely: User-controlled path reaches a filesystem boundary directly.',
            'Fix: Resolve user paths against a fixed base directory.',
            'Validate: Replay ../ payloads and confirm rejection.',
            'Avoid: Strip ../ without canonical checks.',
            'Sources: OWASP Path Traversal',
        ]));
        const discussNode = detailNodes.find(node => node.label === 'Discuss this finding');
        expect(discussNode?.command?.command).toBe('owlvex.discussFinding');
        expect(discussNode?.command?.arguments?.[0]).toMatchObject({ id: 'finding-1', title: 'Path traversal' });
        const fixPreviewNode = detailNodes.find(node => node.label === 'Fix code');
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
                scanTier: 'TARGETED_AI',
                confidenceTier: 'PLAUSIBLE',
                corroboration: 'CORROBORATED',
                likelihood: 'HIGH',
                riskScore: 7,
            }],
            positives: [],
            metrics: { critical: 0, high: 0, medium: 1, low: 0 },
            durationMs: 20,
            model: 'test-model',
            provider: 'test-provider',
            warnings: [],
            projectContextSummary: 'none',
        } as any);

        const severityNode = provider.getChildren().find(item => item.kind === 'severity');
        const findingNode = provider.getChildren(severityNode)[0];
        expect(String(findingNode.tooltip)).toContain('[AI 91%] Dynamic SQL is built from user input.');

        const detailNodes = provider.getChildren(findingNode);
        expect(detailNodes.map(node => node.label)).toContain('AI confidence: 91%');
        expect(detailNodes.map(node => node.label)).toContain('Scan tier: TARGETED_AI');
        expect(detailNodes.map(node => node.label)).toContain('Confidence tier: PLAUSIBLE');
        expect(detailNodes.map(node => node.label)).toContain('Corroboration: CORROBORATED');
        expect(String(provider.getChildren()[0].tooltip)).toContain('Corroboration posture: corroborated: 1');
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
            projectContextSummary: 'none',
        } as any);

        const roots = provider.getChildren();
        expect(String(roots[0].tooltip)).toContain('Coverage posture: partial AI coverage or deterministic-only fallback');
        expect(String(roots[0].tooltip)).toContain('Scan tier posture: none');
        expect(String(roots[0].tooltip)).toContain('Corroboration posture: none');
    });

    it('summarizes mixed corroboration states in the score tooltip', () => {
        const provider = new SidebarProvider();
        provider.refresh({
            scanId: 'scan-4',
            score: 5.9,
            summary: 'Mixed corroboration states.',
            findings: [
                {
                    id: 'finding-proven',
                    line: 5,
                    lineEnd: 5,
                    severity: 'HIGH',
                    framework: 'OWASP',
                    ruleCode: 'SM-002',
                    title: 'Debug mode enabled',
                    explanation: 'Debug mode is active.',
                    threat: 'Information disclosure.',
                    fix: 'Guard debug mode.',
                    confidence: 1,
                    provenance: 'deterministic',
                    scanTier: 'STATIC',
                    confidenceTier: 'PROVEN',
                    corroboration: 'PROVEN',
                    likelihood: 'HIGH',
                    riskScore: 8,
                },
                {
                    id: 'finding-partial',
                    line: 8,
                    lineEnd: 8,
                    severity: 'MEDIUM',
                    framework: 'OWASP',
                    ruleCode: 'OWASP-A01',
                    title: 'Potential IDOR',
                    explanation: 'Access control may be missing.',
                    threat: 'Unauthorized access.',
                    fix: 'Enforce ownership checks.',
                    confidence: 0.81,
                    provenance: 'ai',
                    scanTier: 'TARGETED_AI',
                    confidenceTier: 'PLAUSIBLE',
                    corroboration: 'PARTIAL',
                    likelihood: 'MEDIUM',
                    riskScore: 6,
                },
                {
                    id: 'finding-unverified',
                    line: 12,
                    lineEnd: 12,
                    severity: 'LOW',
                    framework: 'OWASP',
                    ruleCode: 'OWASP-A10',
                    title: 'Potential redirect issue',
                    explanation: 'Redirect target may be untrusted.',
                    threat: 'Phishing.',
                    fix: 'Allow-list destinations.',
                    confidence: 0.62,
                    provenance: 'ai',
                    scanTier: 'TARGETED_AI',
                    confidenceTier: 'PLAUSIBLE',
                    corroboration: 'UNVERIFIED',
                    likelihood: 'LOW',
                    riskScore: 3,
                },
            ],
            positives: [],
            metrics: { critical: 0, high: 1, medium: 1, low: 1 },
            durationMs: 18,
            model: 'test-model',
            provider: 'test-provider',
            warnings: [],
            projectContextSummary: 'inline project contract',
        } as any);

        const roots = provider.getChildren();
        expect(String(roots[0].tooltip)).toContain('Scan tier posture: static: 1 | targeted_ai: 2');
        expect(String(roots[0].tooltip)).toContain('Corroboration posture: proven: 1 | partial: 1 | unverified: 1');
    });
});
