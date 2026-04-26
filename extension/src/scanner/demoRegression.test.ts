import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { ScanEngine } from './scanEngine';

const createJsonResponse = (body: unknown, ok = true, status = 200) => ({
    ok,
    status,
    text: jest.fn().mockResolvedValue(JSON.stringify(body)),
}) as any;

function readRepoFixture(...segments: string[]): string {
    return fs.readFileSync(path.resolve(__dirname, '../../../tools', ...segments), 'utf8');
}

function buildDocument(fileName: string, languageId: string, source: string) {
    return {
        languageId,
        fileName,
        getText: () => source,
    } as any;
}

describe('Demo fixture regression coverage', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: (key: string, defaultValue?: any) => {
                switch (key) {
                    case 'apiUrl':
                        return 'https://api.example.test';
                    case 'frameworks':
                        return ['OWASP'];
                    case 'severityThreshold':
                        return 'MEDIUM';
                    case 'teamContext':
                        return '';
                    default:
                        return defaultValue;
                }
            },
        });
    });

    it('keeps the safe deserialization fixture clean under AI overclassification attempts', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete: jest.fn()
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        score: 7.5,
                        summary: 'Insecure deserialization detected.',
                        findings: [{
                            id: 'demo-safe-deser',
                            line: 9,
                            line_end: 9,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A08-DESER',
                            title: 'Insecure deserialization of untrusted data',
                            explanation: 'User-controlled JSON is deserialized directly.',
                            threat: 'Unexpected data may be parsed from request input.',
                            fix: 'Validate JSON before loading it.',
                            confidence: 0.9,
                            issue_id: 'owlvex.issue.insecure_deserialization.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['The request body is parsed directly from user input.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{ id: 'demo-safe-deser', verdict: 'reject', reason: 'json.loads is data parsing, not executable deserialization.' }],
                    }),
                    tokenCount: 10,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{ id: 'demo-safe-deser', verdict: 'clear', reason: 'No further contradiction needed.' }],
                    }),
                    tokenCount: 10,
                }),
        };

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, { getActive: jest.fn(() => provider) } as any);
        const doc = buildDocument(
            'd:\\repo\\tools\\demo\\27-deserialization-safe.py',
            'python',
            readRepoFixture('demo', '27-deserialization-safe.py'),
        );

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
    });

    it('keeps the guarded debug fixture clean under AI overclassification attempts', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete: jest.fn().mockResolvedValue({
                content: JSON.stringify({
                    score: 8.5,
                    summary: 'Debug mode enabled in production.',
                    findings: [{
                        id: 'demo-safe-debug',
                        line: 16,
                        line_end: 16,
                        severity: 'MEDIUM',
                        framework: 'OWASP',
                        rule_code: 'SM-002',
                        title: 'Debug mode enabled in production',
                        explanation: 'Debug mode is controlled by environment and may be misconfigured.',
                        threat: 'Debug details could leak if config drifts.',
                        fix: 'Disable debug mode in production.',
                        confidence: 0.9,
                        issue_id: 'owlvex.issue.debug_mode_production.001',
                        likelihood: 'MEDIUM',
                        likelihood_reasons: ['Debug mode is present in the file.'],
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            }),
        };

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, { getActive: jest.fn(() => provider) } as any);
        const doc = buildDocument(
            'd:\\repo\\tools\\demo\\04-debug-safe.js',
            'javascript',
            readRepoFixture('demo', '04-debug-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
    });

    it('keeps the allowlisted fetch-safe route clean under SSRF overclassification attempts', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete: jest.fn()
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        score: 5,
                        summary: 'Possible SSRF detected.',
                        findings: [{
                            id: 'safe-fetch-ssrf',
                            line: 12,
                            line_end: 18,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A10-SSRF',
                            title: 'Potential incomplete validation in /fetch-safe endpoint',
                            explanation: 'The URL validation helper may not be sufficient before fetch.',
                            threat: 'Attackers may reach internal services.',
                            fix: 'Tighten outbound URL validation.',
                            confidence: 0.7,
                            issue_id: 'owlvex.issue.ssrf.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['User input still flows into fetch.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{
                            id: 'safe-fetch-ssrf',
                            verdict: 'reject',
                            confidence: 0.92,
                            reason: 'The safe route calls fetchAllowedPartner with a partner key, not a request-controlled URL.',
                        }],
                    }),
                    tokenCount: 12,
                }),
        };

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, { getActive: jest.fn(() => provider) } as any);
        const doc = buildDocument(
            'd:\\repo\\tools\\benchmark-app\\src\\routes\\integrations.js',
            'javascript',
            readRepoFixture('benchmark-app', 'src', 'routes', 'integrations.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.ssrf.001');
        expect(result.findings[0].line).toBe(8);
        expect(result.findings.some(f => f.id === 'safe-fetch-ssrf')).toBe(false);
    });

    it('keeps the benchmark-app server shell clean from route-mount and logging overclaims', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete: jest.fn().mockResolvedValue({
                content: JSON.stringify({
                    score: 3.3,
                    summary: 'Multiple issues detected.',
                    findings: [
                        {
                            id: 'server-csrf-overcall',
                            line: 21,
                            line_end: 27,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A05-CSRF',
                            title: 'Missing CSRF protection on state-changing request',
                            explanation: 'Mounted routes may expose state-changing endpoints without CSRF protection.',
                            threat: 'Attackers could trick users into changing state.',
                            fix: 'Add CSRF protection.',
                            confidence: 0.8,
                            issue_id: 'owlvex.issue.csrf_missing_token.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['State-changing routes are mounted here.'],
                        },
                        {
                            id: 'server-log-overcall',
                            line: 31,
                            line_end: 34,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A09-LOG',
                            title: 'Sensitive data exposed in logs',
                            explanation: 'The displayName field is logged directly.',
                            threat: 'Sensitive data may end up in logs.',
                            fix: 'Avoid logging sensitive values.',
                            confidence: 0.8,
                            issue_id: 'owlvex.issue.sensitive_logging.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['User-controlled data appears in the file.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 2, low: 0 },
                }),
                tokenCount: 42,
            }),
        };

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, { getActive: jest.fn(() => provider) } as any);
        const doc = buildDocument(
            'd:\\repo\\tools\\benchmark-app\\src\\server.js',
            'javascript',
            readRepoFixture('benchmark-app', 'src', 'server.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
    });
});
