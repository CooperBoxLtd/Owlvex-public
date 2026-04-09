export interface FrameworkDefinition {
    code: string;
    name: string;
    version: string;
    category: 'security' | 'quality' | 'compliance' | 'threat-model';
    description: string;
    docsUrl?: string;
}

export const FRAMEWORK_CATALOG: FrameworkDefinition[] = [
    {
        code: 'OWASP',
        name: 'OWASP Top 10',
        version: '2021',
        category: 'security',
        description: 'Current OWASP Top 10 web application security risks baseline.',
        docsUrl: 'https://owasp.org/www-project-top-ten/',
    },
    {
        code: 'STRIDE',
        name: 'STRIDE Threat Model',
        version: '2026.1',
        category: 'threat-model',
        description: 'Owlvex-native versioned threat-model profile for spoofing, tampering, repudiation, disclosure, DoS, and elevation.',
    },
    {
        code: 'CWE',
        name: 'CWE Top Weaknesses',
        version: '4.15',
        category: 'security',
        description: 'MITRE Common Weakness Enumeration weakness taxonomy for software flaws.',
        docsUrl: 'https://cwe.mitre.org/',
    },
    {
        code: 'MITRE',
        name: 'MITRE ATT&CK',
        version: '15',
        category: 'security',
        description: 'Adversary tactics and techniques mapped to code and application behaviors.',
        docsUrl: 'https://attack.mitre.org/',
    },
    {
        code: 'NIST',
        name: 'NIST SP 800-53',
        version: 'Rev. 5',
        category: 'compliance',
        description: 'Security and privacy controls commonly used in regulated environments.',
        docsUrl: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    },
    {
        code: 'PCIDSS',
        name: 'PCI DSS',
        version: '4.0.1',
        category: 'compliance',
        description: 'Payment card data security controls for payment-related systems.',
        docsUrl: 'https://www.pcisecuritystandards.org/document_library',
    },
    {
        code: 'HIPAA',
        name: 'HIPAA Security Rule',
        version: '2024-curated',
        category: 'compliance',
        description: 'Curated healthcare security/privacy-oriented checks for protected health data workflows.',
    },
    {
        code: 'CLEANCODE',
        name: 'Clean Code',
        version: '2024-curated',
        category: 'quality',
        description: 'Maintainability and engineering hygiene checks that complement security findings.',
    },
];

export function getFrameworkDefinition(code: string): FrameworkDefinition | undefined {
    return FRAMEWORK_CATALOG.find(item => item.code === code);
}

export function formatFrameworkLabel(code: string): string {
    const item = getFrameworkDefinition(code);
    return item ? `${item.code} ${item.version}` : code;
}

export function formatFrameworkSummary(codes: string[]): string {
    if (!codes.length) return 'None';
    return codes.map(formatFrameworkLabel).join(', ');
}
