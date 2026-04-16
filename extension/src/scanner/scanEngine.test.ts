/**
 * Unit tests for ScanEngine._parseAIResponse (via the public scanDocument path
 * we test the parser by driving it with mocked provider and backend calls).
 */
import { ScanEngine } from './scanEngine';
import * as vscode from 'vscode';

// We need access to the private parser — use a subclass to expose it.
class TestableScanEngine extends ScanEngine {
    public parse(raw: string) {
        return (this as any)._parseAIResponse(raw);
    }
}

// Minimal mocks — scanDocument is not called in these tests, only _parseAIResponse.
const mockLicenceMgr = {} as any;
const mockRegistry = {} as any;

const engine = new TestableScanEngine(mockLicenceMgr, mockRegistry);

// ---------------------------------------------------------------------------
// _parseAIResponse
// ---------------------------------------------------------------------------
describe('ScanEngine._parseAIResponse', () => {
    const validPayload = {
        score: 7.5,
        summary: 'Two high severity issues found.',
        findings: [
            {
                id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
                line: 10,
                line_end: 12,
                severity: 'HIGH',
                framework: 'OWASP',
                rule_code: 'OWASP-A03',
                title: 'SQL Injection',
                explanation: 'User input concatenated into SQL query.',
                threat: 'Attacker can dump the database.',
                fix: 'Use parameterised queries.',
                plain_language_fix: 'Do not build the SQL by inserting user input into the query string. Keep the SQL fixed and pass the user value separately as a parameter.',
                confidence: 0.95,
            },
        ],
        positives: ['Input validation present on auth endpoints'],
        metrics: { critical: 0, high: 1, medium: 0, low: 0 },
    };

    it('parses a valid JSON response', () => {
        const result = engine.parse(JSON.stringify(validPayload));
        expect(result.score).toBe(7.5);
        expect(result.summary).toBe('Two high severity issues found.');
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].severity).toBe('HIGH');
        expect(result.findings[0].ruleCode).toBe('OWASP-A03');
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.sql_injection.001');
        expect(result.findings[0].canonicalFamilyLabel).toBe('Injection & Execution');
        expect(result.findings[0].plainLanguageFix).toBe('Do not build the SQL by inserting user input into the query string. Keep the SQL fixed and pass the user value separately as a parameter.');
        expect(result.findings[0].stride).toEqual(['Tampering', 'Information Disclosure']);
        expect(result.findings[0].likelihood).toBeUndefined();
        expect(result.positives).toHaveLength(1);
        expect(result.metrics.high).toBe(1);
    });

    it('strips markdown code fences before parsing', () => {
        const wrapped = '```json\n' + JSON.stringify(validPayload) + '\n```';
        const result = engine.parse(wrapped);
        expect(result.score).toBe(7.5);
        expect(result.findings).toHaveLength(1);
    });

    it('strips plain code fences before parsing', () => {
        const wrapped = '```\n' + JSON.stringify(validPayload) + '\n```';
        const result = engine.parse(wrapped);
        expect(result.findings).toHaveLength(1);
    });

    it('throws when JSON is invalid', () => {
        expect(() => engine.parse('This is not JSON at all.')).toThrow(/could not be parsed/i);
    });

    it('throws for empty string', () => {
        expect(() => engine.parse('')).toThrow(/could not be parsed/i);
    });

    it('maps line_end correctly', () => {
        const payload = { ...validPayload, findings: [{ ...validPayload.findings[0], line_end: 20 }] };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].lineEnd).toBe(20);
    });

    it('uses line as lineEnd fallback when line_end missing', () => {
        const finding = { ...validPayload.findings[0] };
        delete (finding as any).line_end;
        const result = engine.parse(JSON.stringify({ ...validPayload, findings: [finding] }));
        expect(result.findings[0].lineEnd).toBe(finding.line);
    });

    it('assigns default score of 5 when score missing', () => {
        const payload = { ...validPayload };
        delete (payload as any).score;
        const result = engine.parse(JSON.stringify(payload));
        expect(result.score).toBe(5);
    });

    it('assigns default confidence when missing', () => {
        const finding = { ...validPayload.findings[0] };
        delete (finding as any).confidence;
        const result = engine.parse(JSON.stringify({ ...validPayload, findings: [finding] }));
        expect(result.findings[0].confidence).toBe(0.8);
    });

    it('handles empty findings array', () => {
        const result = engine.parse(JSON.stringify({ ...validPayload, findings: [] }));
        expect(result.findings).toHaveLength(0);
    });

    it('handles multiple findings', () => {
        const payload = {
            ...validPayload,
            findings: [
                validPayload.findings[0],
                { ...validPayload.findings[0], id: 'other-id', line: 25, severity: 'CRITICAL', rule_code: 'CWE-89' },
            ],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings).toHaveLength(2);
        expect(result.findings[1].severity).toBe('CRITICAL');
        expect(result.findings[1].canonicalId).toBe('owlvex.issue.sql_injection.001');
    });

    it('preserves model-provided canonical fields when present', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                issue_id: 'custom.issue.id',
                stride: ['Tampering'],
                mappings: { cwe: ['CWE-89'] },
                matched_signals: ['sql injection'],
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].canonicalId).toBe('custom.issue.id');
        expect(result.findings[0].stride).toEqual(['Tampering']);
        expect(result.findings[0].mappings).toEqual({
            cwe: ['CWE-89'],
            owasp: [],
            apiOwasp: [],
            attack: [],
            capec: [],
            nist: [],
        });
    });

    it('normalizes string-based canonical fields from the model', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                stride: 'Tampering, Information Disclosure',
                mappings: {
                    cwe: 'CWE-89',
                    owasp: 'A03:2021',
                    api_owasp: 'API8:2023',
                    attack: 'T1190',
                    capec: 'CAPEC-66',
                    nist: 'SI-10, SA-11',
                },
                matched_signals: 'CWE:CWE-89, sql injection',
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].stride).toEqual(['Tampering', 'Information Disclosure']);
        expect(result.findings[0].mappings).toEqual({
            cwe: ['CWE-89'],
            owasp: ['A03:2021'],
            apiOwasp: ['API8:2023'],
            attack: ['T1190'],
            capec: ['CAPEC-66'],
            nist: ['SI-10', 'SA-11'],
        });
        expect(result.findings[0].matchedSignals).toEqual(['CWE:CWE-89', 'sql injection']);
    });

    it('drops malformed mapping entries so canonical mappings can fill the gap', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                mappings: {
                    cwe: 'CWE-89, nope',
                    owasp: 'A03:2021, random-tag',
                    api_owasp: 'API8:2023, nonsense',
                    attack: 'T1190, BAD',
                    capec: 'CAPEC-66, ???',
                    nist: 'SI-10, not-a-control',
                },
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].mappings).toEqual({
            cwe: ['CWE-89'],
            owasp: ['A03:2021'],
            apiOwasp: ['API8:2023'],
            attack: ['T1190'],
            capec: ['CAPEC-66'],
            nist: ['SI-10'],
        });
    });

    it('normalizes shorthand STRIDE values from the model', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                stride: 'T, E, tampering',
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].stride).toEqual(['Tampering', 'Elevation of Privilege']);
    });

    it('drops malformed STRIDE values and falls back to canonical metadata', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                stride: 'bogus, ???',
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].stride).toEqual(['Tampering', 'Information Disclosure']);
    });

    it('softens insecure CORS wording to avoid overclaiming exploitability', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                severity: 'HIGH',
                title: 'Overly permissive CORS policy',
                explanation: 'This can lead to unauthorized access and data exfiltration.',
                threat: 'Attackers can steal sensitive data from any origin.',
                fix: '',
                plain_language_fix: '',
                issue_id: 'owlvex.issue.insecure_cors.001',
                stride: 'E',
                mappings: { cwe: 'bad-value' },
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].explanation).toMatch(/broader than it should be/i);
        expect(result.findings[0].explanation).toMatch(/invalid or inconsistently enforced by browsers/i);
        expect(result.findings[0].threat).toMatch(/may be able to abuse/i);
        expect(result.findings[0].threat).toMatch(/before treating this as a confirmed data-exfiltration path/i);
        expect(result.findings[0].fix).toBe('Restrict CORS origins, methods, and credential use to explicit trusted callers only.');
        expect(result.findings[0].plainLanguageFix).toBe('Do not allow every origin by default. Keep the CORS policy narrow and list only the trusted sites that should call this endpoint.');
        expect(result.findings[0].stride).toEqual(['Elevation of Privilege']);
        expect(result.findings[0].mappings).toEqual({
            cwe: ['CWE-942'],
            owasp: ['A05:2021'],
            apiOwasp: [],
            attack: [],
            capec: [],
            nist: ['SC-7'],
        });
    });

    it('parses likelihood and likelihood reasons when the model provides them', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                likelihood: 'high',
                likelihood_reasons: ['User input reaches a query sink.', 'No validation is visible nearby.'],
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.findings[0].likelihoodReasons).toEqual([
            'User input reaches a query sink.',
            'No validation is visible nearby.',
        ]);
    });

    it('accepts camelCase plainLanguageFix from the model as well', () => {
        const payload = {
            ...validPayload,
            findings: [{
                ...validPayload.findings[0],
                plain_language_fix: undefined,
                plainLanguageFix: 'Keep the SQL static and send the value separately.',
            }],
        };
        const result = engine.parse(JSON.stringify(payload));
        expect(result.findings[0].plainLanguageFix).toBe('Keep the SQL static and send the value separately.');
    });
});

describe('ScanEngine.scanDocument caching', () => {
    const createJsonResponse = (body: unknown, ok = true, status = 200) => ({
        ok,
        status,
        text: jest.fn().mockResolvedValue(JSON.stringify(body)),
    }) as any;

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

    it('reuses licence validation and prompt build across repeated scans with the same settings', async () => {
        const validate = jest.fn().mockResolvedValue({
            valid: true,
            features: { frameworks: ['OWASP'] },
        });
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate,
        } as any;
        const complete = jest.fn().mockResolvedValue({
            content: JSON.stringify({
                score: 8,
                summary: 'ok',
                findings: [],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 0, low: 0 },
            }),
            tokenCount: 42,
        });
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-2' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const firstDoc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\a.js',
            getText: () => 'const a = 1;',
        } as any;
        const secondDoc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\b.js',
            getText: () => 'const b = 2;',
        } as any;

        await engine.scanDocument(firstDoc);
        await engine.scanDocument(secondDoc);

        expect(validate).toHaveBeenCalledTimes(1);
        expect(global.fetch).toHaveBeenCalledTimes(3);
        expect((global.fetch as jest.Mock).mock.calls[0][0]).toContain('/v1/prompts/build');
        expect((global.fetch as jest.Mock).mock.calls[1][0]).toContain('/v1/scans/record');
        expect((global.fetch as jest.Mock).mock.calls[2][0]).toContain('/v1/scans/record');
        expect(complete).toHaveBeenCalledTimes(2);
    });

    it('falls back to deterministic-only results when the backend is unavailable', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockRejectedValue(new Error('connect ECONNREFUSED')),
        } as any;
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete: jest.fn(),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\a.js',
            getText: () => 'exec(`cat ${file}`);',
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('deterministic');
        expect(result.model).toContain('deterministic-only');
        expect(result.warnings[0]).toMatch(/backend unavailable/i);
        expect(provider.complete).not.toHaveBeenCalled();
    });

    it('falls back to deterministic-only results when the AI provider fails', async () => {
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
            complete: jest.fn().mockRejectedValue(new Error('provider timeout')),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\a.js',
            getText: () => 'exec(`cat ${file}`);',
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('deterministic');
        expect(result.findings[0].confidenceTier).toBe('PROVEN');
        expect(result.warnings[0]).toMatch(/AI provider unavailable/i);
        expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('retries transient provider rate limits before succeeding', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const provider = {
            id: 'azure-foundry',
            selectedModel: 'owlvex-gpt54mini',
            complete: jest.fn()
                .mockRejectedValueOnce(new Error('Azure Foundry error: 429'))
                .mockRejectedValueOnce(new Error('Azure Foundry error: 429'))
                .mockResolvedValue({
                    content: JSON.stringify({
                        score: 8,
                        summary: 'ok',
                        findings: [],
                        positives: [],
                        metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    }),
                    tokenCount: 42,
                }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation(((fn: any) => {
            fn();
            return 0 as any;
        }) as any);

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\a.js',
            getText: () => 'const x = 1;',
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.summary).toBe('No findings detected.');
        expect(provider.complete).toHaveBeenCalledTimes(3);
        setTimeoutSpy.mockRestore();
    });

    it('suppresses conflicting AI findings when a deterministic IDOR finding already covers the region', async () => {
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
                    score: 3.5,
                    summary: 'AI added an extra issue.',
                    findings: [
                        {
                            id: 'ai-1',
                            line: 1,
                            line_end: 6,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'OWASP-A03',
                            title: 'Command Injection',
                            explanation: 'Incorrect AI overcall for the same function.',
                            threat: 'Arbitrary command execution.',
                            fix: 'Sanitize shell input.',
                            confidence: 0.61,
                            issue_id: 'owlvex.issue.code_injection.eval.001',
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\01-idor-unsafe.js',
            getText: () => `async function getDocument(currentUser, docId, db) {
    const doc = await db.query(
        'SELECT * FROM documents WHERE id = ?',
        [docId],
    );
    return doc;
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].ruleCode).toBe('AC-001');
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.idor.001');
        expect(result.findings[0].canonicalFamilyLabel).toBe('Access Control & Authorization');
        expect(result.score).toBe(9);
    });

    it('recalculates the final score from merged severity metrics instead of trusting the model score', async () => {
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
                    score: 2.5,
                    summary: 'Critical vulnerability detected.',
                    findings: [
                        {
                            id: 'ai-1',
                            line: 7,
                            line_end: 7,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'SM-001',
                            title: 'Insecure Cookie',
                            explanation: 'Cookie is readable by client-side script.',
                            threat: 'Session theft via XSS.',
                            fix: 'Set httpOnly.',
                            confidence: 0.91,
                            issue_id: 'owlvex.issue.insecure_cookie.001',
                        },
                    ],
                    positives: [],
                    metrics: { critical: 1, high: 0, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\10-cookie-unsafe.js',
            getText: () => `function issueSessionCookie(req, res, token) {
    res.cookie('session', token);
    res.json({ ok: true });
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.metrics).toEqual({ critical: 0, high: 0, medium: 1, low: 0 });
        expect(result.score).toBe(7);
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.findings[0].riskScore).toBe(7);
        expect(result.summary).toBe('1 finding(s) detected, led by 1 medium-severity issue(s). File risk score is driven by the highest remaining finding risk: medium impact x high likelihood = 7/10. Issue families: Identity & Auth Failures.');
    });

    it('preserves AI-only findings for issue classes not covered by the deterministic engine yet', async () => {
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
                    score: 6.4,
                    summary: 'Potential open redirect detected.',
                    findings: [
                        {
                            id: 'ai-open-redirect-1',
                            line: 2,
                            line_end: 2,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A01-REDIRECT',
                            title: 'Open Redirect',
                            explanation: 'User-controlled destination is passed directly into a redirect call.',
                            threat: 'Attackers can steer users to attacker-controlled pages.',
                            fix: 'Allow-list redirect destinations.',
                            confidence: 0.88,
                            issue_id: 'owlvex.issue.open_redirect.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['The redirect destination comes straight from request input.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\redirect.js',
            getText: () => `function go(req, res) {
    return res.redirect(req.query.next);
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('ai');
        expect(result.findings[0].confidence).toBe(0.92);
        expect(result.findings[0].confidenceTier).toBe('PLAUSIBLE');
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.open_redirect.001');
        expect(result.findings[0].canonicalFamilyLabel).toBe('Security Misconfiguration & Platform Hardening');
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.score).toBe(7);
    });

    it('keeps AI-only CSRF findings distinct from deterministic coverage', async () => {
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
                    score: 4.5,
                    summary: 'Missing CSRF protection detected.',
                    findings: [
                        {
                            id: 'ai-csrf-1',
                            line: 1,
                            line_end: 6,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A01-CSRF',
                            title: 'Missing CSRF protection',
                            explanation: 'A state-changing browser request is accepted without a CSRF token check.',
                            threat: 'Attackers can trick an authenticated browser into performing an unwanted action.',
                            fix: 'Require anti-CSRF tokens or same-site protections.',
                            confidence: 0.84,
                            issue_id: 'owlvex.issue.csrf_missing_token.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['The request mutates account data and no CSRF token validation is visible.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\csrf.js',
            getText: () => `function updateEmail(req, res, db) {
    db.query(
        'UPDATE users SET email = ? WHERE id = ?',
        [req.body.email, req.session.userId],
    );
    res.json({ ok: true });
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('ai');
        expect(result.findings[0].confidence).toBe(0.92);
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.csrf_missing_token.001');
        expect(result.findings[0].canonicalFamilyLabel).toBe('Access Control & Authorization');
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.score).toBe(9);
    });

    it('keeps AI-only SSRF findings distinct from deterministic coverage', async () => {
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
                    score: 4.5,
                    summary: 'Possible SSRF detected.',
                    findings: [
                        {
                            id: 'ai-ssrf-1',
                            line: 2,
                            line_end: 2,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A10-SSRF',
                            title: 'Server-side request forgery',
                            explanation: 'A server-side HTTP request is made to a URL controlled by the user.',
                            threat: 'Attackers can pivot requests into internal services or metadata endpoints.',
                            fix: 'Allow only trusted outbound hosts and block internal address ranges.',
                            confidence: 0.83,
                            issue_id: 'owlvex.issue.ssrf.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['The outbound fetch destination is taken directly from request input.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\ssrf.js',
            getText: () => `async function fetchAvatar(req, res, fetch) {
    const response = await fetch(req.query.url);
    const body = await response.text();
    res.send(body);
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('ai');
        expect(result.findings[0].confidence).toBe(0.92);
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.ssrf.001');
        expect(result.findings[0].canonicalFamilyLabel).toBe('Injection & Execution');
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.score).toBe(9);
    });

    it('keeps AI-only weak JWT validation findings distinct from deterministic coverage', async () => {
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
                    score: 4.5,
                    summary: 'Weak JWT validation detected.',
                    findings: [
                        {
                            id: 'ai-jwt-1',
                            line: 2,
                            line_end: 2,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A07-JWT',
                            title: 'Weak JWT validation',
                            explanation: 'JWT claims are decoded without a signature verification step.',
                            threat: 'Attackers can forge or tamper with tokens and impersonate other users.',
                            fix: 'Verify the token signature, algorithm, issuer, and audience explicitly.',
                            confidence: 0.82,
                            issue_id: 'owlvex.issue.weak_jwt_validation.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['The code decodes the token and no verification call is visible.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\jwt.js',
            getText: () => `function readClaims(token, jwt) {
    return jwt.decode(token);
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('ai');
        expect(result.findings[0].confidence).toBe(0.92);
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.weak_jwt_validation.001');
        expect(result.findings[0].canonicalFamilyLabel).toBe('Identity & Auth Failures');
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.score).toBe(9);
    });

    it('keeps AI-only insecure deserialization findings distinct from deterministic coverage', async () => {
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
                    score: 4.5,
                    summary: 'Insecure deserialization detected.',
                    findings: [
                        {
                            id: 'ai-deser-1',
                            line: 4,
                            line_end: 4,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A08-DESER',
                            title: 'Insecure deserialization',
                            explanation: 'A pickle payload from the request is deserialized directly.',
                            threat: 'Attackers can trigger malicious object materialization or code execution paths.',
                            fix: 'Replace unsafe deserialization with safe data-only parsing and validation.',
                            confidence: 0.81,
                            issue_id: 'owlvex.issue.insecure_deserialization.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['The request body is passed into pickle.loads without validation or signing.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'python',
            fileName: 'd:\\repo\\deser.py',
            getText: () => `import pickle

def load_profile(request):
    return pickle.loads(request.body)
`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].provenance).toBe('ai');
        expect(result.findings[0].confidence).toBe(0.92);
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.insecure_deserialization.001');
        expect(result.findings[0].canonicalFamilyLabel).toBe('Injection & Execution');
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.score).toBe(9);
    });

    it('suppresses AI-only insecure deserialization findings for data-only json parsing', async () => {
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
                    score: 7.5,
                    summary: 'Insecure deserialization detected.',
                    findings: [
                        {
                            id: 'ai-deser-fp-1',
                            line: 4,
                            line_end: 4,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A08-DESER',
                            title: 'Insecure deserialization',
                            explanation: 'User-controlled JSON is deserialized directly.',
                            threat: 'Unexpected data may be parsed from request input.',
                            fix: 'Validate JSON before loading it.',
                            confidence: 0.9,
                            issue_id: 'owlvex.issue.insecure_deserialization.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['The request body is parsed directly from user input.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'python',
            fileName: 'd:\\repo\\deser-safe.py',
            getText: () => `import json

def load_profile(request):
    payload = json.loads(request.body)
    return {
        "name": payload.get("name"),
        "role": payload.get("role"),
    }
`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.score).toBe(0);
        expect(result.summary).toContain('No findings');
    });

    it('suppresses AI-only debug-mode findings when debug activation is properly guarded', async () => {
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
                    findings: [
                        {
                            id: 'ai-debug-fp-1',
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
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\04-debug-safe.js',
            getText: () => `const express = require('express');
const app = express();

if (process.env.NODE_ENV !== 'production') {
    app.set('debug', true);
}
`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.score).toBe(0);
        expect(result.summary).toBe('No findings detected.');
    });

    it('suppresses AI-only access-control findings when the helper enforces tenant scoping', async () => {
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
                    score: 2.0,
                    summary: 'Broken access control detected.',
                    findings: [
                        {
                            id: 'ai-idor-safe-1',
                            line: 2,
                            line_end: 2,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A01-IDOR',
                            title: 'Broken Access Control in getDocumentForTenant',
                            explanation: 'The helper returns a document without enough access control checks.',
                            threat: 'Attackers could access another document.',
                            fix: 'Add tenant validation.',
                            confidence: 0.9,
                            issue_id: 'owlvex.issue.idor.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['Resource access is derived from caller input.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\db.js',
            getText: () => `function getDocumentForTenant(id, tenantId) {
  return documents.find((doc) => doc.id === id && doc.tenantId === tenantId);
}
`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.score).toBe(0);
        expect(result.summary).toBe('No findings detected.');
    });

    it('suppresses AI-only SSRF findings when an outbound URL allowlist check gates fetch', async () => {
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
                    score: 5.0,
                    summary: 'Possible SSRF detected.',
                    findings: [
                        {
                            id: 'ai-ssrf-safe-1',
                            line: 3,
                            line_end: 8,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A10-SSRF',
                            title: 'Potential incomplete validation in fetch-safe endpoint',
                            explanation: 'The URL validation helper may not be sufficient before fetch.',
                            threat: 'Attackers may reach internal services.',
                            fix: 'Tighten outbound URL validation.',
                            confidence: 0.7,
                            issue_id: 'owlvex.issue.ssrf.001',
                            likelihood: 'MEDIUM',
                            likelihood_reasons: ['User input still flows into fetch.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\integrations.js',
            getText: () => `router.get('/fetch-safe', async (req, res) => {
  if (!isAllowedOutboundUrl(req.query.url)) {
    return res.status(400).json({ error: 'outbound_url_blocked' });
  }

  const response = await fetch(req.query.url);
  const body = await response.text();
  res.json({ ok: true, body });
});
`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.score).toBe(0);
        expect(result.summary).toBe('No findings detected.');
    });

    it('deduplicates overlapping AI findings for the same canonical issue', async () => {
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
                    score: 1.0,
                    summary: 'SQL injection detected.',
                    findings: [
                        {
                            id: 'ai-sqli-1',
                            line: 2,
                            line_end: 4,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A03-SQLI',
                            title: 'Unsanitized SQL query construction',
                            explanation: 'User input is concatenated into SQL.',
                            threat: 'Attackers can inject SQL.',
                            fix: 'Use parameterized queries.',
                            confidence: 0.62,
                            issue_id: 'owlvex.issue.sql_injection.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['Input is concatenated into a query string.'],
                        },
                        {
                            id: 'ai-sqli-2',
                            line: 3,
                            line_end: 4,
                            severity: 'HIGH',
                            framework: 'OWASP',
                            rule_code: 'A03-SQLI',
                            title: 'Unsafe SQL query in findUsersByEmailUnsafe',
                            explanation: 'The same SQL string is built with direct interpolation.',
                            threat: 'Attackers can inject SQL.',
                            fix: 'Use parameterized queries.',
                            confidence: 1,
                            issue_id: 'owlvex.issue.sql_injection.001',
                            likelihood: 'HIGH',
                            likelihood_reasons: ['The same sink is described twice.'],
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 2, medium: 0, low: 0 },
                }),
                tokenCount: 42,
            }),
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\db.js',
            getText: () => `function findUsersByEmailUnsafe(email) {
  return {
    sql: \`SELECT id, email FROM users WHERE email = '\${email}'\`,
  };
}
`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].canonicalId).toBe('owlvex.issue.sql_injection.001');
        expect(result.findings[0].confidence).toBe(1);
    });

    it('injects curated framework and cheat-sheet grounding into the AI request', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: (key: string, defaultValue?: any) => {
                switch (key) {
                    case 'apiUrl':
                        return 'https://api.example.test';
                    case 'frameworks':
                        return ['OWASP', 'CWE'];
                    case 'severityThreshold':
                        return 'MEDIUM';
                    case 'teamContext':
                        return '';
                    default:
                        return defaultValue;
                }
            },
        });

        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP', 'CWE'] },
            }),
        } as any;
        const complete = jest.fn().mockResolvedValue({
            content: JSON.stringify({
                score: 8,
                summary: 'ok',
                findings: [],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 0, low: 0 },
            }),
            tokenCount: 42,
        });
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\cmd.js',
            getText: () => 'exec(`cat ${file}`);',
        } as any;

        await engine.scanDocument(doc);

        const userMessage = complete.mock.calls[0][0].userMessage as string;
        expect(userMessage).toContain('Grounded framework guidance:');
        expect(userMessage).toContain('Selected frameworks for this scan: OWASP, CWE');
        expect(userMessage).toContain('OWASP: OWASP Top 10 (2021)');
        expect(userMessage).toContain('CWE: Common Weakness Enumeration');
        expect(userMessage).toContain('Grounded remediation guidance:');
        expect(userMessage).toContain('owlvex.issue.command_injection.001:');
        expect(userMessage).toContain('Cheat sheet guidance: OWASP OS Command Injection Defense Cheat Sheet:');
    });

    it('injects bounded candidate issue grounding for AI-only classes suggested by the code', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: (key: string, defaultValue?: any) => {
                switch (key) {
                    case 'apiUrl':
                        return 'https://api.example.test';
                    case 'frameworks':
                        return ['OWASP', 'CWE'];
                    case 'severityThreshold':
                        return 'MEDIUM';
                    case 'teamContext':
                        return '';
                    default:
                        return defaultValue;
                }
            },
        });

        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP', 'CWE'] },
            }),
        } as any;
        const complete = jest.fn().mockResolvedValue({
            content: JSON.stringify({
                score: 8,
                summary: 'ok',
                findings: [],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 0, low: 0 },
            }),
            tokenCount: 42,
        });
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\cors.js',
            getText: () => [
                'function enableCors(app) {',
                '  app.use((req, res, next) => {',
                "    res.setHeader('Access-Control-Allow-Origin', '*');",
                "    res.setHeader('Access-Control-Allow-Credentials', 'true');",
                '    next();',
                '  });',
                '}',
            ].join('\n'),
        } as any;

        await engine.scanDocument(doc);

        const userMessage = complete.mock.calls[0][0].userMessage as string;
        expect(userMessage).toContain('Grounded candidate issues for AI-only analysis:');
        expect(userMessage).toContain('owlvex.issue.insecure_cors.001 | Overly permissive CORS policy');
        expect(userMessage).toContain('Signals matched in code: cors, access-control-allow-origin');
        expect(userMessage).toContain('Cheat-sheet guidance: OWASP Cross Origin Resource Sharing Cheat Sheet');
    });

    it('runs finder, verifier, and skeptic passes through the same provider sequentially', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const complete = jest.fn()
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 6.4,
                    summary: 'Potential open redirect detected.',
                    findings: [
                        {
                            id: 'ai-open-redirect-1',
                            line: 2,
                            line_end: 2,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A01-REDIRECT',
                            title: 'Open Redirect',
                            explanation: 'User-controlled destination is passed directly into a redirect call.',
                            threat: 'Attackers can steer users to attacker-controlled pages.',
                            fix: 'Allow-list redirect destinations.',
                            confidence: 0.88,
                            issue_id: 'owlvex.issue.open_redirect.001',
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            })
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    reviews: [
                        { id: 'ai-open-redirect-1', verdict: 'support', reason: 'The redirect sink is directly fed by request input.' },
                    ],
                }),
                tokenCount: 10,
            })
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    reviews: [
                        { id: 'ai-open-redirect-1', verdict: 'clear', reason: 'No allow-list or guard is visible.' },
                    ],
                }),
                tokenCount: 10,
            });
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\redirect.js',
            getText: () => `function go(req, res) {
    return res.redirect(req.query.next);
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(complete).toHaveBeenCalledTimes(3);
        expect(complete.mock.calls[0][0].userMessage).toContain('Analyse this javascript code.');
        expect(complete.mock.calls[1][0].userMessage).toContain('You are the Verifier pass.');
        expect(complete.mock.calls[2][0].userMessage).toContain('You are the Skeptic pass.');
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].confidence).toBe(0.92);
        expect(result.findings[0].corroboration).toBe('CORROBORATED');
        expect(result.warnings).toEqual([]);
    });

    it('suppresses AI findings rejected by the verifier pass', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const complete = jest.fn()
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 7.5,
                    summary: 'Potential open redirect detected.',
                    findings: [
                        {
                            id: 'ai-open-redirect-2',
                            line: 2,
                            line_end: 2,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A01-REDIRECT',
                            title: 'Open Redirect',
                            explanation: 'User-controlled destination is passed directly into a redirect call.',
                            threat: 'Attackers can steer users to attacker-controlled pages.',
                            fix: 'Allow-list redirect destinations.',
                            confidence: 0.81,
                            issue_id: 'owlvex.issue.open_redirect.001',
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            })
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    reviews: [
                        { id: 'ai-open-redirect-2', verdict: 'reject', reason: 'The redirect destination is not actually user-controlled in the local code context.' },
                    ],
                }),
                tokenCount: 10,
            })
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    reviews: [
                        { id: 'ai-open-redirect-2', verdict: 'clear', reason: 'No additional contradiction beyond the verifier rejection.' },
                    ],
                }),
                tokenCount: 10,
            });
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\redirect.js',
            getText: () => `function go(req, res) {
    return res.redirect(req.query.next);
}
`,
        } as any;

        const result = await engine.scanDocument(doc);

        expect(result.findings).toHaveLength(0);
        expect(result.summary).toBe('No findings detected.');
        expect(complete).toHaveBeenCalledTimes(3);
    });

    it('skips verifier and skeptic passes when AI candidate count exceeds corroboration budget', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const findings = Array.from({ length: 5 }, (_, index) => ({
            id: `ai-finding-${index + 1}`,
            line: index + 2,
            line_end: index + 2,
            severity: 'MEDIUM',
            framework: 'OWASP',
            rule_code: `A01-${index + 1}`,
            title: `Issue ${index + 1}`,
            explanation: 'Potential issue from finder pass.',
            threat: 'Potential abuse.',
            fix: 'Investigate.',
            confidence: 0.74,
            issue_id: `owlvex.issue.synthetic_${index + 1}.001`,
        }));
        const complete = jest.fn().mockResolvedValueOnce({
            content: JSON.stringify({
                score: 4.8,
                summary: 'Several candidates detected.',
                findings,
                positives: [],
                metrics: { critical: 0, high: 0, medium: 5, low: 0 },
            }),
            tokenCount: 42,
        });
        const provider = {
            id: 'openai',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\bulk.js',
            getText: () => 'function a() { return true; }',
        } as any;

        const result = await engine.scanDocument(doc);

        expect(complete).toHaveBeenCalledTimes(1);
        expect(result.findings).toHaveLength(5);
        expect(result.findings.every(finding => finding.corroboration === 'UNVERIFIED')).toBe(true);
        expect(result.warnings.join('\n')).toContain('AI corroboration partial: review passes skipped because candidate count 5 exceeded corroboration budget 4.');
    });

    it('keeps findings but marks corroboration partial when verifier or skeptic passes are unavailable', async () => {
        const licenceMgr = {
            getKey: jest.fn().mockResolvedValue('licence-key'),
            validate: jest.fn().mockResolvedValue({
                valid: true,
                features: { frameworks: ['OWASP'] },
            }),
        } as any;
        const complete = jest.fn()
            .mockResolvedValueOnce({
                content: JSON.stringify({
                    score: 6.4,
                    summary: 'Potential open redirect detected.',
                    findings: [
                        {
                            id: 'ai-open-redirect-partial',
                            line: 2,
                            line_end: 2,
                            severity: 'MEDIUM',
                            framework: 'OWASP',
                            rule_code: 'A01-REDIRECT',
                            title: 'Open Redirect',
                            explanation: 'User-controlled destination is passed directly into a redirect call.',
                            threat: 'Attackers can steer users to attacker-controlled pages.',
                            fix: 'Allow-list redirect destinations.',
                            confidence: 0.88,
                            issue_id: 'owlvex.issue.open_redirect.001',
                        },
                    ],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                }),
                tokenCount: 42,
            })
            .mockRejectedValue(new Error('Azure Foundry error: 429 retry-after: 1'));
        const provider = {
            id: 'azure-foundry',
            selectedModel: 'gpt-4o',
            complete,
        };
        const registry = {
            getActive: jest.fn(() => provider),
        } as any;

        (global.fetch as jest.Mock) = jest.fn()
            .mockResolvedValueOnce(createJsonResponse({
                system_prompt: 'prompt-body',
                template_id: 'prompt-1',
            }))
            .mockResolvedValueOnce(createJsonResponse({ scan_id: 'scan-1' }));

        const setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation(((fn: any) => {
            fn();
            return 0 as any;
        }) as any);

        const engine = new ScanEngine(licenceMgr, registry);
        const doc = {
            languageId: 'javascript',
            fileName: 'd:\\repo\\redirect.js',
            getText: () => `function go(req, res) {
    return res.redirect(req.query.next);
}`,
        } as any;

        const result = await engine.scanDocument(doc);

        setTimeoutSpy.mockRestore();
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].corroboration).toBe('UNVERIFIED');
        expect(result.warnings.join('\n')).toContain('AI corroboration partial: verifier pass unavailable');
        expect(result.warnings.join('\n')).toContain('AI corroboration partial: skeptic pass skipped after verifier rate-limit pressure.');
        expect(complete).toHaveBeenCalledTimes(5);
    });
});
