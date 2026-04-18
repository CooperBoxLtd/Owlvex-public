export type DeterministicLanguage =
    | 'javascript-typescript'
    | 'python'
    | 'java'
    | 'csharp'
    | 'go';

export interface IssueProofContract {
    issueId: string;
    contractLabel: string;
    familyId: string;
    proofBoundary: string;
    supportedDeterministicLanguages: DeterministicLanguage[];
    notClaimedDeterministicLanguages: DeterministicLanguage[];
    safePatternExpectations: string[];
}

export const PROOF_TRACKED_LANGUAGES: DeterministicLanguage[] = [
    'javascript-typescript',
    'python',
    'java',
    'csharp',
    'go',
];

export const ISSUE_PROOF_CONTRACTS: IssueProofContract[] = [
    {
        issueId: 'owlvex.issue.sql_injection.001',
        contractLabel: 'SQL Injection',
        familyId: 'family.injection_execution',
        proofBoundary: 'Only fire when request-derived or attacker-controlled values are structurally visible inside SQL text reaching a query sink. Keep quiet when parameter binding or prepared statements are visible.',
        supportedDeterministicLanguages: ['javascript-typescript', 'python', 'java', 'csharp', 'go'],
        notClaimedDeterministicLanguages: [],
        safePatternExpectations: ['parameter binding', 'prepared statements', 'placeholder-based query APIs'],
    },
    {
        issueId: 'owlvex.issue.command_injection.001',
        contractLabel: 'Command Injection',
        familyId: 'family.injection_execution',
        proofBoundary: 'Only fire when untrusted input is structurally embedded into shell command text or equivalent dangerous execution syntax. Keep quiet when the executable is fixed and arguments stay out of shell parsing.',
        supportedDeterministicLanguages: ['javascript-typescript', 'python', 'java', 'csharp', 'go'],
        notClaimedDeterministicLanguages: [],
        safePatternExpectations: ['fixed executable plus validated argument list', 'shell disabled', 'safe library API instead of shell execution'],
    },
    {
        issueId: 'owlvex.issue.path_traversal.001',
        contractLabel: 'Path Traversal',
        familyId: 'family.access_control',
        proofBoundary: 'Only fire when request-derived path input visibly reaches a filesystem sink without a directory-boundary check. Keep quiet when normalize-and-boundary validation is visible.',
        supportedDeterministicLanguages: ['javascript-typescript', 'python', 'java', 'csharp', 'go'],
        notClaimedDeterministicLanguages: [],
        safePatternExpectations: ['normalized path under fixed base directory', 'server-side identifier map', 'path boundary enforcement'],
    },
    {
        issueId: 'owlvex.issue.ssrf.001',
        contractLabel: 'Server-Side Request Forgery',
        familyId: 'family.injection_execution',
        proofBoundary: 'Only fire when request-derived destinations visibly reach outbound request sinks without a host allowlist or equivalent destination control. Keep quiet when allowlisted outbound routing is visible.',
        supportedDeterministicLanguages: ['javascript-typescript', 'python', 'java', 'csharp', 'go'],
        notClaimedDeterministicLanguages: [],
        safePatternExpectations: ['exact host allowlist', 'named integration map', 'validated outbound destination wrapper'],
    },
    {
        issueId: 'owlvex.issue.weak_jwt_validation.001',
        contractLabel: 'Weak JWT Validation',
        familyId: 'family.identity_auth',
        proofBoundary: 'Only fire when tokens are decoded or parsed without signature verification or equivalent trust checks. Keep quiet when verified parsing with an explicit key function or verifier is visible.',
        supportedDeterministicLanguages: ['javascript-typescript', 'python', 'java', 'go'],
        notClaimedDeterministicLanguages: ['csharp'],
        safePatternExpectations: ['jwt verify APIs', 'explicit verifier builder', 'visible key function for token verification'],
    },
    {
        issueId: 'owlvex.issue.insecure_deserialization.001',
        contractLabel: 'Insecure Deserialization',
        familyId: 'family.injection_execution',
        proofBoundary: 'Only fire when unsafe object deserializers are visibly used on untrusted input. Keep quiet for data-only parsing such as JSON and schema-validated DTO flows.',
        supportedDeterministicLanguages: ['python', 'java'],
        notClaimedDeterministicLanguages: ['javascript-typescript', 'csharp', 'go'],
        safePatternExpectations: ['data-only formats', 'schema validation before use', 'restricted DTO-only parsing'],
    },
    {
        issueId: 'owlvex.issue.idor.001',
        contractLabel: 'Missing Object-Level Authorization',
        familyId: 'family.access_control',
        proofBoundary: 'Only fire when object lookup or mutation is structurally visible without an owner, tenant, or policy scope. Keep quiet when object access is clearly bound to actor context.',
        supportedDeterministicLanguages: ['javascript-typescript'],
        notClaimedDeterministicLanguages: ['python', 'java', 'csharp', 'go'],
        safePatternExpectations: ['owner or tenant scope in query', 'explicit authorization policy', 'repository method already bound to actor context'],
    },
    {
        issueId: 'owlvex.issue.open_redirect.001',
        contractLabel: 'Open Redirect',
        familyId: 'family.security_misconfiguration',
        proofBoundary: 'Only fire when request-derived redirect destinations are visibly used without an allowlist or same-origin check. Keep quiet when redirect destinations are validated or route-mapped.',
        supportedDeterministicLanguages: ['javascript-typescript'],
        notClaimedDeterministicLanguages: ['python', 'java', 'csharp', 'go'],
        safePatternExpectations: ['redirect allowlist', 'same-origin validation', 'server-side route name mapping'],
    },
    {
        issueId: 'owlvex.issue.csrf_missing_token.001',
        contractLabel: 'Missing CSRF Protection',
        familyId: 'family.access_control',
        proofBoundary: 'Only fire on state-changing browser-session flows where visible CSRF protection is absent. Keep quiet when anti-CSRF token validation or equivalent same-site protection is visible.',
        supportedDeterministicLanguages: ['javascript-typescript'],
        notClaimedDeterministicLanguages: ['python', 'java', 'csharp', 'go'],
        safePatternExpectations: ['anti-CSRF token validation', 'state parameter validation where applicable', 'same-site browser protection visible in flow'],
    },
];

export function getIssueProofContract(issueId: string): IssueProofContract | undefined {
    return ISSUE_PROOF_CONTRACTS.find(contract => contract.issueId === issueId);
}
