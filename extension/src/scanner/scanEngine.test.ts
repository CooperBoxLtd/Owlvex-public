/**
 * Unit tests for ScanEngine._parseAIResponse (via the public scanDocument path
 * we test the parser by driving it with mocked provider and backend calls).
 */
import { ScanEngine } from './scanEngine';

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
});
