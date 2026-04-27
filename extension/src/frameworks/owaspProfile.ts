import { PROFILE } from '../profile';

export type OwaspTop10Version = '2021' | '2025';

export interface OwaspFrameworkDetails {
    version: OwaspTop10Version;
    description: string;
    docsUrl: string;
    promptGuidance: string[];
    reportFocus: string[];
}

export const OWASP_2025_CATEGORIES = [
    'A01:2025 Broken Access Control',
    'A02:2025 Security Misconfiguration',
    'A03:2025 Software Supply Chain Failures',
    'A04:2025 Cryptographic Failures',
    'A05:2025 Injection',
    'A06:2025 Insecure Design',
    'A07:2025 Authentication Failures',
    'A08:2025 Software or Data Integrity Failures',
    'A09:2025 Security Logging and Alerting Failures',
    'A10:2025 Mishandling of Exceptional Conditions',
] as const;

const OWASP_2021_TO_2025: Record<string, string | undefined> = {
    A01: 'A01:2025',
    A02: 'A04:2025',
    A03: 'A05:2025',
    A04: 'A06:2025',
    A05: 'A02:2025',
    A06: 'A03:2025',
    A07: 'A07:2025',
    A08: 'A08:2025',
    A09: 'A09:2025',
};

function normalizeOwaspCode(value: string): string {
    const match = value.trim().toUpperCase().match(/^(A\d{2})(?::\d{4})?$/);
    return match?.[1] ?? value.trim().toUpperCase();
}

export function getOwaspTop10Version(): OwaspTop10Version {
    const configuredVersion = (PROFILE as { owaspTop10Version?: string }).owaspTop10Version;
    return configuredVersion === '2025' ? '2025' : '2021';
}

export function getOwaspFrameworkDetails(): OwaspFrameworkDetails {
    if (getOwaspTop10Version() === '2025') {
        return {
            version: '2025',
            description: 'Current OWASP Top 10 web application security risks baseline for development validation.',
            docsUrl: 'https://owasp.org/Top10/2025/',
            promptGuidance: [
                'Use OWASP Top 10:2025 category names and identifiers when OWASP is selected.',
                'Prefer 2025 category language for development scans, while preserving underlying evidence and CWE grounding.',
                'Do not force a 2025 category when the evidence only supports a narrower issue label.',
            ],
            reportFocus: [
                'OWASP 2025 risk area',
                'developer action',
                'evidence-backed mapping',
            ],
        };
    }

    return {
        version: '2021',
        description: 'OWASP Top 10 2021 web application security risks baseline.',
        docsUrl: 'https://owasp.org/Top10/2021/',
        promptGuidance: [
            'Prefer OWASP category labels only when the code evidence supports the mapped risk area.',
            'Use OWASP to explain the class of weakness, not as proof by itself.',
            'Keep remediation practical and developer-facing rather than compliance-heavy.',
        ],
        reportFocus: [
            'application risk area',
            'developer-friendly explanation',
            'short remediation summary',
        ],
    };
}

export function formatOwaspMappingForActiveProfile(value: string): string {
    if (getOwaspTop10Version() !== '2025') {
        return value;
    }

    if (value.toUpperCase().endsWith(':2025')) {
        return value;
    }

    const mapped = OWASP_2021_TO_2025[normalizeOwaspCode(value)];
    if (!mapped) {
        return `${value} (legacy; no direct OWASP 2025 equivalent)`;
    }

    return `${mapped} (from ${value})`;
}

export function getOwaspMappingAliasesForActiveProfile(value: string): string[] {
    const normalized = normalizeOwaspCode(value);
    const aliases = new Set([value.trim().toUpperCase()]);
    if (getOwaspTop10Version() === '2025') {
        const mapped = OWASP_2021_TO_2025[normalized];
        if (mapped) {
            aliases.add(mapped);
        }
    }
    return [...aliases];
}
