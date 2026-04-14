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

        expect(result.summary).toBe('ok');
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
        expect(result.score).toBe(6.3);
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
        expect(result.score).toBe(7.8);
        expect(result.findings[0].likelihood).toBe('HIGH');
        expect(result.findings[0].riskScore).toBe(7);
        expect(result.summary).toBe('1 finding(s) detected, led by 1 medium-severity issue(s). Highest contextual risk: medium impact x high likelihood = 7/10. Issue families: Identity & Auth Failures.');
    });
});
