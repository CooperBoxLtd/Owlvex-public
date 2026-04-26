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

    it('feeds a local sink inventory into the Finder prompt before AI review', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 0,
                    summary: 'No findings detected.',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
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
            'd:\\repo\\tools\\demo\\22-ssrf-unsafe.js',
            'javascript',
            readRepoFixture('demo', '22-ssrf-unsafe.js'),
        );

        const result = await engine.scanDocument(doc);

        const userMessage = provider.complete.mock.calls[0][0].userMessage;
        expect(userMessage).toContain('Local sink inventory before AI:');
        expect(userMessage).toContain('family=ssrf');
        expect(userMessage).toContain('sink=outbound-request');
        expect(userMessage).toContain('Sink-first evidence beats generic suspicion.');
        expect(result.engineTelemetry?.sinkInventory.total).toBeGreaterThan(0);
        expect(result.engineTelemetry?.sinkInventory.byFamily.ssrf).toBeGreaterThan(0);
        expect(result.engineTelemetry?.aiFindings.proposed).toBe(0);
        expect(result.engineTelemetry?.aiFindings.finalSurvivors).toBe(0);
    });

    it('drops probeable AI candidates before verifier when no matching local sink exists', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 8,
                    summary: 'Possible SSRF detected.',
                    findings: [{
                        id: 'ssrf-without-sink',
                        line: 3,
                        line_end: 3,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        rule_code: 'A10-SSRF',
                        title: 'Server-side request forgery through untrusted destination',
                        explanation: 'The route allegedly fetches an untrusted URL.',
                        threat: 'Attackers may reach internal services.',
                        fix: 'Validate outbound destinations.',
                        confidence: 0.82,
                        issue_id: 'owlvex.issue.ssrf.001',
                        likelihood: 'HIGH',
                        likelihood_reasons: ['The model claimed a request-controlled destination.'],
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
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
            'd:\\repo\\src\\profile.js',
            'javascript',
            [
                'export function profile(req, res) {',
                '  const name = String(req.query.name || "guest");',
                '  res.json({ name });',
                '}',
            ].join('\n'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.engineTelemetry?.sinkInventory.byFamily.ssrf ?? 0).toBe(0);
        expect(result.engineTelemetry?.aiFindings.proposed).toBe(1);
        expect(result.engineTelemetry?.aiFindings.afterStaticFilter).toBe(0);
        expect(result.engineTelemetry?.aiFindings.finalSurvivors).toBe(0);
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

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['insecure-deserialization']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
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

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['debug-exposure']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops CSRF overcalls when a state-changing route validates a CSRF token', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 7,
                    summary: 'Possible CSRF issue detected.',
                    findings: [{
                        id: 'safe-csrf-overcall',
                        line: 7,
                        line_end: 7,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        rule_code: 'A01-CSRF',
                        title: 'State-changing request missing CSRF protection',
                        explanation: 'The route updates a user email using browser session state.',
                        threat: 'Attackers may trigger cross-site requests.',
                        fix: 'Require and validate a CSRF token.',
                        confidence: 0.84,
                        issue_id: 'owlvex.issue.csrf_missing_token.001',
                        likelihood: 'HIGH',
                        likelihood_reasons: ['A browser-authenticated update is visible.'],
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
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
            'd:\\repo\\tools\\demo\\19-csrf-safe.js',
            'javascript',
            readRepoFixture('demo', '19-csrf-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily.csrf).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops sensitive logging overcalls when the log payload is redacted metadata', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 6,
                    summary: 'Possible sensitive logging detected.',
                    findings: [{
                        id: 'safe-log-overcall',
                        line: 7,
                        line_end: 10,
                        severity: 'MEDIUM',
                        framework: 'OWASP',
                        rule_code: 'DP-001',
                        title: 'Sensitive credential written to logs',
                        explanation: 'A login handler logs credential-related fields.',
                        threat: 'Secrets may be retained in log systems.',
                        fix: 'Redact secrets before logging.',
                        confidence: 0.79,
                        issue_id: 'owlvex.issue.sensitive_logging.001',
                        likelihood: 'MEDIUM',
                        likelihood_reasons: ['The logging call is near a supplied secret value.'],
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
            'd:\\repo\\tools\\demo\\13-sensitive-logging-safe.js',
            'javascript',
            readRepoFixture('demo', '13-sensitive-logging-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['sensitive-logging']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops IDOR overcalls when object access is scoped to the current user', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 8,
                    summary: 'Possible IDOR detected.',
                    findings: [{
                        id: 'safe-idor-overcall',
                        line: 6,
                        line_end: 9,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        rule_code: 'A01-IDOR',
                        title: 'Missing object-level authorization',
                        explanation: 'The document id reaches a database query.',
                        threat: 'Attackers may read another user document.',
                        fix: 'Scope document access to the actor.',
                        confidence: 0.86,
                        issue_id: 'owlvex.issue.idor.001',
                        likelihood: 'HIGH',
                        likelihood_reasons: ['A document id is used in a lookup.'],
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
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
            'd:\\repo\\tools\\demo\\02-idor-safe.js',
            'javascript',
            readRepoFixture('demo', '02-idor-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['object-authorization']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops privileged action overcalls when an admin guard protects the route', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 8,
                    summary: 'Possible unprotected admin route.',
                    findings: [{
                        id: 'safe-admin-overcall',
                        line: 14,
                        line_end: 17,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        rule_code: 'A01-BFLA',
                        title: 'Unprotected admin route',
                        explanation: 'The admin route triggers a privileged rebuild action.',
                        threat: 'Unauthorized users may trigger maintenance actions.',
                        fix: 'Require an admin role before the action.',
                        confidence: 0.85,
                        issue_id: 'owlvex.issue.unprotected_admin_route.001',
                        likelihood: 'HIGH',
                        likelihood_reasons: ['An admin route invokes a privileged service.'],
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
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
            'd:\\repo\\tools\\demo\\81-unprotected-admin-route-safe.js',
            'javascript',
            readRepoFixture('demo', '81-unprotected-admin-route-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['privileged-action']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops mass-assignment overcalls when request fields are projected explicitly', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 7,
                    summary: 'Possible mass assignment detected.',
                    findings: [{
                        id: 'safe-mass-assignment-overcall',
                        line: 7,
                        line_end: 10,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        rule_code: 'A01-MASS',
                        title: 'Mass assignment through request body',
                        explanation: 'The profile update uses request body fields.',
                        threat: 'Attackers may set privileged fields.',
                        fix: 'Use an explicit field allowlist.',
                        confidence: 0.81,
                        issue_id: 'owlvex.issue.mass_assignment.001',
                        likelihood: 'MEDIUM',
                        likelihood_reasons: ['Request body values are used in an update.'],
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
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
            'd:\\repo\\tools\\demo\\79-mass-assignment-safe.js',
            'javascript',
            readRepoFixture('demo', '79-mass-assignment-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['mass-assignment']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops NoSQL injection overcalls when query fields are projected explicitly', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 7,
                    summary: 'Possible NoSQL injection detected.',
                    findings: [{
                        id: 'safe-nosql-overcall',
                        line: 16,
                        line_end: 16,
                        severity: 'HIGH',
                        framework: 'OWASP',
                        rule_code: 'A03-NOSQL',
                        title: 'NoSQL injection through untrusted query object',
                        explanation: 'Request body values influence a Mongo query.',
                        threat: 'Attackers may inject Mongo operators.',
                        fix: 'Build queries from explicit fields.',
                        confidence: 0.82,
                        issue_id: 'owlvex.issue.nosql_injection.001',
                        likelihood: 'MEDIUM',
                        likelihood_reasons: ['Request body values are used before users.find.'],
                    }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
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
            'd:\\repo\\tools\\demo\\77-nosql-injection-safe.js',
            'javascript',
            readRepoFixture('demo', '77-nosql-injection-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['nosql-injection']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.aiFindings.finalSurvivors).toBe(0);
    });

    it('drops audit-gap overcalls when a privileged action records an audit event', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 6,
                    summary: 'Possible audit gap detected.',
                    findings: [{
                        id: 'safe-audit-overcall',
                        line: 14,
                        line_end: 18,
                        severity: 'MEDIUM',
                        framework: 'OWASP',
                        rule_code: 'LOG-001',
                        title: 'Missing audit trail for privileged action',
                        explanation: 'The handler suspends an account.',
                        threat: 'Privileged changes may lack traceability.',
                        fix: 'Record actor, action, and target audit metadata.',
                        confidence: 0.78,
                        issue_id: 'owlvex.issue.audit_gap.001',
                        likelihood: 'MEDIUM',
                        likelihood_reasons: ['A privileged account action is visible.'],
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
            'd:\\repo\\tools\\demo\\85-audit-gap-safe.js',
            'javascript',
            readRepoFixture('demo', '85-audit-gap-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['audit-gap']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops PII overexposure overcalls when responses use safe projection', async () => {
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
            complete: jest.fn().mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 7,
                    summary: 'Possible PII overexposure detected.',
                    findings: [{
                        id: 'safe-pii-overcall',
                        line: 9,
                        line_end: 13,
                        severity: 'MEDIUM',
                        framework: 'OWASP',
                        rule_code: 'DP-002',
                        title: 'PII overexposure in API response',
                        explanation: 'The profile endpoint returns account data.',
                        threat: 'Sensitive account fields may leak.',
                        fix: 'Return only fields required by the client.',
                        confidence: 0.8,
                        issue_id: 'owlvex.issue.pii_overexposure.001',
                        likelihood: 'MEDIUM',
                        likelihood_reasons: ['Account data is returned in JSON.'],
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
            'd:\\repo\\tools\\demo\\87-pii-overexposure-safe.js',
            'javascript',
            readRepoFixture('demo', '87-pii-overexposure-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['pii-overexposure']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops verifier-supported CORS overcalls when the sink probe sees an origin allowlist', async () => {
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
                        score: 6,
                        summary: 'Possible CORS issue detected.',
                        findings: [{
                            id: 'safe-cors-overcall',
                            line: 11,
                            line_end: 12,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'CORS-001',
                            title: 'Overly permissive CORS policy',
                            explanation: 'The response allows credentials for request origins.',
                            threat: 'Attackers may abuse cross-origin browser access.',
                            fix: 'Constrain CORS origins.',
                            confidence: 0.78,
                            issue_id: 'owlvex.issue.insecure_cors.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['The Origin header influences CORS response headers.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{
                            id: 'safe-cors-overcall',
                            verdict: 'support',
                            confidence: 0.91,
                            reason: 'The Origin header affects Access-Control-Allow-Origin.',
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
            'd:\\repo\\tools\\demo\\21-cors-safe.js',
            'javascript',
            readRepoFixture('demo', '21-cors-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily.cors).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
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
                            verdict: 'support',
                            confidence: 0.95,
                            reason: 'The route still passes request input toward an outbound request helper.',
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

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.ssrf.001');
        expect(result.findings[0].line).toBe(8);
        expect(result.findings.some(f => f.id === 'safe-fetch-ssrf')).toBe(false);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops verifier-supported SQL injection overcalls when the sink probe sees parameter binding', async () => {
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
                        score: 7,
                        summary: 'Possible SQL injection detected.',
                        findings: [{
                            id: 'safe-sql-overcall',
                            line: 7,
                            line_end: 10,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A03-SQLI',
                            title: 'SQL injection through user-controlled email',
                            explanation: 'The email value reaches a SQL query.',
                            threat: 'Attackers may alter the query.',
                            fix: 'Use parameterized queries.',
                            confidence: 0.75,
                            issue_id: 'owlvex.issue.sql_injection.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['User input is used in a query call.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{
                            id: 'safe-sql-overcall',
                            verdict: 'support',
                            confidence: 0.91,
                            reason: 'The user-controlled email value reaches the db.query call.',
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
            'd:\\repo\\tools\\demo\\07-sqli-safe.js',
            'javascript',
            readRepoFixture('demo', '07-sqli-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
    });

    it('drops verifier-supported open redirect overcalls when the sink probe sees a local route allowlist', async () => {
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
                        score: 6,
                        summary: 'Possible open redirect detected.',
                        findings: [{
                            id: 'safe-redirect-overcall',
                            line: 9,
                            line_end: 9,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A01-REDIRECT',
                            title: 'Open redirect through untrusted next parameter',
                            explanation: 'The next value reaches res.redirect.',
                            threat: 'Attackers may send users to a phishing site.',
                            fix: 'Constrain redirect destinations.',
                            confidence: 0.76,
                            issue_id: 'owlvex.issue.open_redirect.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['The request next parameter influences the redirect target.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{
                            id: 'safe-redirect-overcall',
                            verdict: 'support',
                            confidence: 0.91,
                            reason: 'The next parameter influences res.redirect.',
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
            'd:\\repo\\tools\\demo\\17-open-redirect-safe.js',
            'javascript',
            readRepoFixture('demo', '17-open-redirect-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.sinkInventory.byFamily['open-redirect']).toBeGreaterThan(0);
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops verifier-supported command injection overcalls when the sink probe sees argv separation', async () => {
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
                        score: 7,
                        summary: 'Possible command injection detected.',
                        findings: [{
                            id: 'safe-command-overcall',
                            line: 8,
                            line_end: 8,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A03-CMD',
                            title: 'Command injection through username',
                            explanation: 'The username reaches process execution.',
                            threat: 'Attackers may execute shell syntax.',
                            fix: 'Use argument arrays.',
                            confidence: 0.76,
                            issue_id: 'owlvex.issue.command_injection.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['User input is used in process execution.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{
                            id: 'safe-command-overcall',
                            verdict: 'support',
                            confidence: 0.91,
                            reason: 'The username reaches a process execution call.',
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
            'd:\\repo\\tools\\demo\\09-command-injection-safe.js',
            'javascript',
            readRepoFixture('demo', '09-command-injection-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
    });

    it('drops verifier-supported path traversal overcalls when the sink probe sees a file allowlist', async () => {
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
                        score: 7,
                        summary: 'Possible path traversal detected.',
                        findings: [{
                            id: 'safe-path-overcall',
                            line: 17,
                            line_end: 20,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A01-PATH',
                            title: 'Path traversal through selected file',
                            explanation: 'The selected filename reaches sendFile.',
                            threat: 'Attackers may access arbitrary files.',
                            fix: 'Constrain file names.',
                            confidence: 0.78,
                            issue_id: 'owlvex.issue.path_traversal.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['A request-controlled selector influences a file path.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{
                            id: 'safe-path-overcall',
                            verdict: 'support',
                            confidence: 0.91,
                            reason: 'The selected value influences a file sent to the user.',
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
            'd:\\repo\\tools\\demo\\29-path-traversal-safe.js',
            'javascript',
            readRepoFixture('demo', '29-path-traversal-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
    });

    it('drops verifier-supported weak JWT overcalls when the sink probe sees explicit verification', async () => {
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
                        score: 7,
                        summary: 'Possible weak JWT validation detected.',
                        findings: [{
                            id: 'safe-jwt-overcall',
                            line: 6,
                            line_end: 10,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A07-JWT',
                            title: 'Weak JWT validation',
                            explanation: 'The token is read for claims.',
                            threat: 'Attackers may forge claims.',
                            fix: 'Verify token signatures and claims.',
                            confidence: 0.77,
                            issue_id: 'owlvex.issue.weak_jwt_validation.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['JWT claims are used.'],
                        }],
                        positives: [],
                        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    }),
                    tokenCount: 42,
                })
                .mockResolvedValueOnce({
                    content: JSON.stringify({
                        reviews: [{
                            id: 'safe-jwt-overcall',
                            verdict: 'support',
                            confidence: 0.91,
                            reason: 'The token is accepted and claims are returned.',
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
            'd:\\repo\\tools\\demo\\25-jwt-validation-safe.js',
            'javascript',
            readRepoFixture('demo', '25-jwt-validation-safe.js'),
        );

        const result = await engine.scanDocument(doc);

        expect(provider.complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(result.engineTelemetry?.safeProbes.run).toBe(1);
        expect(result.engineTelemetry?.safeProbes.dropped).toBe(1);
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
