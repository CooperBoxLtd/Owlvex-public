import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs/promises';
import { ProviderRegistry } from '../providers/registry';
import { collectScannableFiles } from '../scanner/workspaceScanner';
import { formatFrameworkSummary } from '../frameworks/catalog';
import { getGroundedCheatSheetLabelsForIssueIds, resolveRemediationForFinding } from '../frameworks/remediationResolver';
import { getGroundedFrameworkLabels } from '../frameworks/frameworkGrounding';
import type { StoredScanRecord } from '../scanner/calibrationReview';
import type { Finding, ProviderDisagreementProof, ScanResult } from '../scanner/scanEngine';
import { PROFILE } from '../profile';
import { getProjectContextSummaryFromConfig, getProjectRootSummaryFromConfig, loadProjectContextInfo, resolveProjectRootInfo } from '../projectContext';
import { createPreviewDocumentUri } from './previewDocumentProvider';
import { buildLicenceStatusSummary, buildPlanNextStepGuidance, buildPlanUpgradeMessage, hasAiAssistantAccess, LicenceManager } from '../licence/licenceManager';

type ChatRole = 'user' | 'assistant' | 'system';
type MessageKind = 'advisory' | 'scan';
type ConversationMode = 'scan' | 'repo' | 'fix' | 'general';

interface RecentScanSnapshot {
    provider: string;
    model: string;
    findingCount: number;
    score: number;
}

interface ChatMessage {
    role: ChatRole;
    content: string;
    kind?: MessageKind;
    actions?: ChatMessageAction[];
}

type ChatMessageActionKind =
    | 'openSource'
    | 'applyFixPreview'
    | 'discardFixPreview'
    | 'generateFixPreview'
    | 'generateBatchFixPreview'
    | 'restorePreviousChat'
    | 'dismissMessage'
    | 'explainScore'
    | 'quickAction';

interface ChatMessageAction {
    id: string;
    label: string;
    kind: ChatMessageActionKind;
    quickAction?: string;
    path?: string;
    line?: number;
    finding?: Finding;
    findings?: ActionableFindingTarget[];
    calibrationRecords?: StoredScanRecord[];
}

interface EditorContext {
    summary: string;
    promptContext: string;
}

interface UserPromptOptions {
    displayedPrompt?: string;
    injectedContext?: string;
    suggestedFinding?: Finding;
}

interface FindingDiscussionContext {
    promptContext: string;
    sourceSummary: string;
}

interface FindingContextBundle {
    promptContext: string;
    sourceSummary: string;
    sourceActions: ChatMessageAction[];
}

interface PendingFixPreview {
    targetPath: string;
    originalText: string;
    patchedText: string;
    title: string;
    finding: Finding;
    reviewedPaths?: string[];
    changes?: Array<{
        targetPath: string;
        originalText: string;
        patchedText: string;
        title: string;
        finding: Finding;
    }>;
}

interface GenerateFixPreviewOptions {
    reuseCurrentTurn?: boolean;
}

interface ActionableFindingTarget {
    finding: Finding;
    targetPath?: string;
}

interface LocalActionResult {
    handled: boolean;
    response?: string;
    kind?: MessageKind;
    actions?: ChatMessageAction[];
}

type ChatActionKind = 'scanFile' | 'scanSelectedFiles' | 'scanOpenEditors' | 'scanFolder' | 'scanReport' | 'scanSummaryReport' | 'scanFullReport' | 'reviewRiskCalibration';

interface ChatLocalIntent {
    action: ChatActionKind;
    fileHint?: string;
}

interface ChatState {
    provider: string;
    providerId: string;
    model: string;
    models: string[];
    providers: Array<{ id: string; name: string }>;
    providerStatus: string;
    providerHint: string;
    providerConfigured: boolean;
    backendStatus: string;
    licenceStatus: string;
    hasLicence: boolean;
    hasStoredLicenceKey: boolean;
    messages: ChatMessage[];
    editorSummary: string;
    frameworksLabel: string;
    severityThreshold: string;
    projectContextSummary: string;
    workspaceSummary: string;
    lastScanTarget: string;
    hasLastScan: boolean;
    conversationStatus: string;
    hasRestorableChat: boolean;
    restorableMessageCount: number;
    workingScope: WorkingScope;
    workingScopeLabel: string;
    activeMode: ConversationMode;
    activeModeLabel: string;
    activeModeHint: string;
}

type WorkingScope = 'scanFile' | 'scanSelectedFiles' | 'scanOpenEditors' | 'scanFolder';

function normalizeReviewedPath(filePath: string): string {
    return path.normalize(filePath).toLowerCase();
}

function getReviewedPathSet(preview: PendingFixPreview): Set<string> {
    const reviewed = preview.reviewedPaths?.length
        ? preview.reviewedPaths
        : preview.changes?.map(change => change.targetPath) ?? [preview.targetPath];
    return new Set(reviewed.map(normalizeReviewedPath));
}

const CHAT_STATE_KEY = `${PROFILE.storagePrefix}.chat.messages`;
const LAST_SCAN_TARGET_KEY = `${PROFILE.storagePrefix}.chat.lastScanTarget`;
const LAST_REPORT_SNAPSHOT_KEY = `${PROFILE.storagePrefix}.lastReportSnapshot`;
const WORKING_SCOPE_KEY = `${PROFILE.storagePrefix}.chat.workingScope`;
const FIX_BENCHMARK_MANIFEST_RELATIVE_PATH = path.join('tools', 'fix-benchmark', 'fix-benchmark.expectations.json');
const FIX_BENCHMARK_RESULTS_RELATIVE_PATH = path.join('tools', 'fix-benchmark', 'fix-benchmark.latest.json');

interface FixBenchmarkExpectation {
    caseId: string;
    file: string;
}

interface FixBenchmarkManifest {
    name?: string;
    expectations?: FixBenchmarkExpectation[];
}

interface FixBenchmarkRunRecord {
    caseId: string;
    attempted: boolean;
    previewGenerated: boolean;
    appliedCleanly: boolean;
    filesChanged: string[];
    syntaxValid: boolean | null;
    targetFindingRemoved: boolean | null;
    introducedHighRiskFindings: boolean | null;
    notes?: string;
}

interface FixBenchmarkResultsFile {
    benchmark?: string;
    description?: string;
    runs: FixBenchmarkRunRecord[];
}

interface FixBenchmarkUpdate {
    targetUri: vscode.Uri;
    finding: Finding;
    reviewedPaths: string[];
    appliedCleanly: boolean;
    patchedText?: string;
    rescanned?: ScanResult;
    matchingFinding?: Finding;
    notes?: string;
}
type UsageTelemetryEventName =
    | 'fix_preview_generated'
    | 'fix_preview_applied'
    | 'fix_preview_discarded'
    | 'fix_verification_completed';

type UsageTelemetryEmitter = (eventName: UsageTelemetryEventName, metadata?: Record<string, unknown>) => void;
const MAX_PERSISTED_MESSAGES = 40;
const CONTEXT_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.cs', '.go', '.rs', '.php', '.rb', '.cpp', '.c', '.h'];
const DEFAULT_WORKING_SCOPE: WorkingScope = 'scanFolder';
const WORKSPACE_CONTEXT_FILES = ['README.md', 'package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'pom.xml'];
const MAX_SINGLE_FILE_REWRITE_RATIO = 0.75;
const MAX_REWRITE_LINE_THRESHOLD = 20;
const MAX_RECENT_CHAT_CONTEXT_MESSAGES = 8;
const MAX_RECENT_CHAT_CONTEXT_CHARS = 4000;

interface ImportedSymbolContext {
    specifier: string;
    importedNames: string[];
}

function summarizeIssueFamilies(findings: Array<{ canonicalFamilyLabel?: string; canonicalFamily?: string }>): string {
    const labels = [...new Set(
        findings
            .map(item => item.canonicalFamilyLabel || item.canonicalFamily)
            .filter((value): value is string => Boolean(value))
    )];

    if (!labels.length) {
        return 'Issue families: unresolved';
    }

    return `Issue families: ${labels.join(', ')}`;
}

function getFindingLikelihood(finding: Finding): string {
    return String(finding.likelihood ?? 'MEDIUM').toUpperCase();
}

function getScanTierLabel(finding: Finding): string {
    return finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI');
}

function getScanTierDisplayLabel(value: string): string {
    switch (value) {
        case 'STATIC':
            return 'Static proof';
        case 'TARGETED_AI':
            return 'Targeted AI review';
        case 'REPO_AI':
            return 'Repo-context AI review';
        default:
            return value;
    }
}

function getCorroborationDisplayLabel(value: string): string {
    switch (value) {
        case 'PROVEN':
            return 'Proven';
        case 'CORROBORATED':
            return 'Corroborated';
        case 'PARTIAL':
            return 'Partial';
        case 'UNVERIFIED':
            return 'Unverified';
        default:
            return value;
    }
}

function summarizeScanTierCounts(findings: Finding[]): string {
    const order: Array<'STATIC' | 'TARGETED_AI' | 'REPO_AI'> = ['STATIC', 'TARGETED_AI', 'REPO_AI'];
    const counts = new Map<string, number>();

    for (const finding of findings) {
        const label = getScanTierLabel(finding);
        counts.set(label, (counts.get(label) ?? 0) + 1);
    }

    return order
        .filter(label => (counts.get(label) ?? 0) > 0)
        .map(label => `${label.toLowerCase()}: ${counts.get(label)}`)
        .join(' | ') || 'none';
}

function getPrimaryScanTierLabel(findings: Finding[]): string {
    const order: Array<'REPO_AI' | 'TARGETED_AI' | 'STATIC'> = ['REPO_AI', 'TARGETED_AI', 'STATIC'];
    for (const label of order) {
        if (findings.some(finding => getScanTierLabel(finding) === label)) {
            return label;
        }
    }

    return 'none';
}

function buildDefaultChatMessages(): ChatMessage[] {
    return [];
}

function isWorkingScope(value: string): value is WorkingScope {
    return value === 'scanFile'
        || value === 'scanSelectedFiles'
        || value === 'scanOpenEditors'
        || value === 'scanFolder';
}

function getWorkingScopeLabel(scope: WorkingScope): string {
    switch (scope) {
        case 'scanFile':
            return 'Current file';
        case 'scanSelectedFiles':
            return 'Selected files';
        case 'scanOpenEditors':
            return 'Open editors';
        case 'scanFolder':
        default:
            return 'Workspace';
    }
}

function getConversationModeLabel(mode: ConversationMode): string {
    switch (mode) {
        case 'scan':
            return 'Scan';
        case 'fix':
            return 'Fix';
        case 'general':
            return 'General';
        case 'repo':
        default:
            return 'Repo Q&A';
    }
}

function getConversationModeHint(mode: ConversationMode): string {
    switch (mode) {
        case 'scan':
            return 'Scanner behavior: findings, reports, and scan-backed evidence.';
        case 'fix':
            return 'Fix behavior: finding-anchored remediation and previewed code changes.';
        case 'general':
            return 'General behavior: free-form help without implicit scan or repo-grounded claims.';
        case 'repo':
        default:
            return 'Repo Q&A behavior: grounded explanation, not an implied scan result.';
    }
}

function looksLikeRepoQuestion(prompt: string): boolean {
    return /\b(repo|repository|workspace|project|codebase|app|application|module|folder|directory|readme|package\.json|server\.js|route|routes|middleware|helper|entrypoint|what does .* do|how does .* work|where is|which file|explain the app)\b/i.test(prompt);
}

function riskRank(finding: Finding): number {
    return (finding.riskScore ?? 0) * 10 + severityRank(finding.severity);
}

function looksLikeFixRequest(prompt: string): boolean {
    return /\b(fix|patch|replace|rewrite|safe version|secure version|implement|apply|remediate|solution)\b/i.test(prompt);
}

function looksLikeImplementRequest(prompt: string): boolean {
    return /\b(implement( this| the)? change|change it in the file|change the file|edit the file|apply( the)? fix|apply( the)? change|apply( the)? changes|apply it|make the change|make the changes|update the file|do it)\b/i.test(prompt);
}

function looksLikeFindingFollowUp(prompt: string): boolean {
    return /\b(explain( the)? finding|explain findings|how( can| could)? (this|it) be exploit(?:ed)?|how is (this|it) exploit(?:ed)?|why is (this|it) dangerous|why is (this|it) vulnerable|this one|that one|the one in the diff|show me|why|how)\b/i.test(prompt);
}

function isRateLimitError(error: unknown): boolean {
    return /\b429\b|rate limit/i.test(String((error as any)?.message ?? error ?? ''));
}

function buildFindingFallback(
    prompt: string,
    finding: Finding,
    intro: string,
    targetPath?: string,
    hasPendingFixPreview = false,
): { content: string; actions?: ChatMessageAction[] } {
    const title = finding.canonicalTitle || finding.title;
    const exploitPrompt = /\b(exploit(?:ed)?|abuse|attack(?:er)?|dangerous|why)\b/i.test(prompt);
    const fixPrompt = looksLikeFixRequest(prompt) || looksLikeImplementRequest(prompt);
    const lines: string[] = [
        intro,
        `Active finding: ${title} at line ${finding.line}.`,
    ];

    if (exploitPrompt) {
        lines.push(`Why it matters: ${finding.explanation}`);
        lines.push(`How it can be abused: ${finding.threat}`);
    } else {
        lines.push(`What is wrong: ${finding.explanation}`);
        lines.push(`What to change: ${finding.fix}`);
    }

    if (fixPrompt || hasPendingFixPreview) {
        lines.push(
            hasPendingFixPreview
                ? 'A fix preview is already open for review. The file is still unchanged until you choose Keep fix or Discard fix.'
                : 'Next step: choose Preview fix to open a side-by-side remediation diff.'
        );
    }

    const actions = targetPath
        ? [buildReviewFixAction(finding, targetPath)]
        : undefined;

    return {
        content: lines.join('\n'),
        actions,
    };
}

function shouldUseLatestScanContext(prompt: string, options: UserPromptOptions): boolean {
    if (options.injectedContext || options.suggestedFinding) {
        return true;
    }

    return /\b(latest|last|previous|recent)\b.*\b(scan|report|finding|findings|issue|issues|result|results|score|scores|risk|risks|warning|warnings)\b/i.test(prompt)
        || /\b(scan|report|finding|findings|issue|issues|result|results|score|scores|risk|risks|warning|warnings)\b.*\b(latest|last|previous|recent)\b/i.test(prompt);
}

function looksLikeToolHelpRequest(prompt: string): boolean {
    return (
        /\b(how|what|where|when|which|explain|help|guide|use|using|start|setup|configure|onboard|next|now|stuck)\b/i.test(prompt)
        && /\b(owlvex|tool|scan|scanner|report|summary report|full evidence|confidence|manual review|fix first|fix code|compare reports?|create report|workspace|selected files|open editors|licen[cs]e|llm|provider|model|first run|first use|install)\b/i.test(prompt)
    )
        || /\b(what now|what next|next step|guide me|getting started|where do i start|what should i click|what should i do first)\b/i.test(prompt);
}

function buildToolUsageGuidance(): string {
    return [
        'Owlvex tool workflow:',
        '- Use the scan scope dropdown to choose Current file, Selected files, Open editors, or Workspace, then press Scan.',
        '- Use the report type dropdown to choose Summary report or Full evidence report, then press Create Report.',
        '- Summary report is the default developer view: what to fix first, confirmed or AI-reviewed issues, manual-review items, and short code evidence.',
        '- Full evidence report is for deeper review: all findings by file, confidence posture, AI pass details, mappings, remediation, coverage, warnings, and scan errors.',
        '- Evidence labels matter: Static proof is strongest; AI-reviewed is supported by review; Partially validated and Needs manual review should be checked before acting.',
        '- Raw AI percentages are audit trace only. They should not be treated as proof by themselves.',
        '- Fix First is the recommended starting point, not a guarantee that lower-ranked findings are unimportant.',
        '- Preview fix opens a side-by-side remediation diff. Code is not changed until the user keeps the fix.',
        '- Compare reports should be used after rescanning; Owlvex orders reports by generation time so Before is the earlier report and After is the later report.',
        '- Provider throttle guidance appears only when a scan sees a 429 or rate-limit warning.',
        '- When users ask how to use Owlvex, give the next concrete click/action and explain which report or scan scope fits their goal.',
    ].join('\n');
}

function buildToolHelpResponse(prompt: string): { content: string; actions?: ChatMessageAction[] } {
    const onboardingFocused = /\b(first run|first use|getting started|where do i start|what should i click|what should i do first|what next|what now|next step|guide me|onboard|install|stuck)\b/i.test(prompt);
    const setupFocused = /\b(setup|configure|licen[cs]e|llm|provider|model|api key|trial|free)\b/i.test(prompt);
    const reportFocused = /\b(report|summary|full evidence|confidence|manual review|fix first|compare)\b/i.test(prompt);
    const scanFocused = /\b(scan|scanner|workspace|current file|selected files|open editors)\b/i.test(prompt);
    const confidenceFocused = /\b(confidence|manual review|confirmed|ai-reviewed|validated|static rule|finder|verifier|skeptic)\b/i.test(prompt);
    const fixFocused = /\b(fix|fix code|preview|keep fix|discard|remediate)\b/i.test(prompt);
    const compareFocused = /\b(compare|before|after|baseline|current|increase|decrease|regression)\b/i.test(prompt);

    const lines = onboardingFocused
        ? [
            'Start here:',
            '',
            '1. Confirm access: use Free, Start Trial, or Enter Licence.',
            '2. Configure the LLM provider you want Owlvex to use.',
            '3. Select the project root if this workspace has more than one app.',
            '4. Run a Workspace scan for broad value, or Current file for the fastest signal.',
            '5. Open the Summary report first. Use the Full evidence report only when you need audit detail.',
            '',
            'Best first click: Onboarding. It checks backend, licence, project root, and LLM readiness.',
        ]
        : setupFocused
            ? [
                'Setup path:',
                '',
                'Licence: choose Use Free, Start Trial, or Enter Licence.',
                'LLM: choose Configure LLM, then select the provider/model and enter the required key or endpoint.',
                'Project root: choose Project Root when Owlvex should stay inside a specific app folder.',
                'Validation: choose Test Connection for the LLM, or Onboarding to check the full path.',
                '',
                'After setup, run a Current file scan for speed or Workspace scan for project-level signal.',
            ]
            : compareFocused
                ? [
                    'Use report comparison after you have at least two reports.',
                    '',
                    'Recommended flow:',
                    '1. Scan and create a report before changes.',
                    '2. Apply or preview fixes.',
                    '3. Rescan and create a new report.',
                    '4. Run Compare Latest Reports.',
                    '',
                    'Owlvex orders reports by generation time: earlier report is Before, later report is After. That prevents false increase/decrease direction if reports are selected backwards.',
                ]
                : confidenceFocused
                    ? [
                        'How to read confidence:',
                        '',
                        'Static proof: strongest signal. Deterministic code structure matched a rule and evidence contract.',
                        'AI-reviewed: AI found the issue and review supported it.',
                        'Partially validated: some evidence supports it, but verification is incomplete.',
                        'Needs manual review: useful candidate, but do not treat it as confirmed yet.',
                        'AI signal percentages: audit trace only. Use the evidence label for decisions.',
                        '',
                        'Use Fix First for priority, but check manual-review findings before acting.',
                    ]
                    : fixFocused
                        ? [
                            'Fix flow:',
                            '',
                            '1. Start from a finding or Fix First item.',
                            '2. Choose Preview fix.',
                            '3. Owlvex opens a side-by-side preview.',
                            '4. Review the change.',
                            '5. Choose Keep fix only if the preview is right. Otherwise choose Discard fix.',
                            '',
                            'Owlvex should not silently modify files; fixes stay in preview until you accept them.',
                        ]
                        : reportFocused
                            ? [
                                'Use reports as two views of the same scan.',
                                '',
                                'Summary report: start here. It shows what to fix first, the strongest findings, manual-review items, and short code evidence.',
                                'Full evidence report: use this when you need audit detail, framework mappings, AI review trail, coverage, warnings, and all findings by file.',
                                '',
                                'Controls: choose the report type from the dropdown beside Create Report, then press Create Report.',
                                'Reading confidence: Static proof is strongest; AI-reviewed is supported; Partially validated and Needs manual review should be checked before acting. Raw AI percentages are audit trace only.',
                            ]
                            : scanFocused
                                ? [
                                    'Use the scan scope dropdown first, then press Scan.',
                                    '',
                                    'Current file: fastest check for the active file.',
                                    'Selected files: focused review of files you choose.',
                                    'Open editors: checks the files you are already working in.',
                                    'Workspace: broader project scan using the selected project root.',
                                    '',
                                    'After the scan, start with Fix First or create a Summary report for the shortest action view.',
                                ]
                                : [
                                    'Owlvex workflow:',
                                    '',
                                    '1. Configure licence and LLM.',
                                    '2. Pick a scan scope and press Scan.',
                                    '3. Create a Summary report for what to fix first.',
                                    '4. Use Full evidence report when you need detailed validation.',
                                    '5. Use Preview fix to review a change before keeping it.',
                                ];

    const reportActions: ChatMessageAction[] = [
        {
            id: 'tool-help-summary-report',
            label: 'Create Summary',
            kind: 'quickAction',
            quickAction: 'scanSummaryReport',
        },
        {
            id: 'tool-help-full-report',
            label: 'Create Full Report',
            kind: 'quickAction',
            quickAction: 'scanFullReport',
        },
    ];
    const setupActions: ChatMessageAction[] = [
        buildQuickActionAction('tool-help-use-free', 'Use Free', 'useFree'),
        buildQuickActionAction('tool-help-start-trial', 'Start Trial', 'startTrial'),
        buildQuickActionAction('tool-help-configure-llm', 'Configure LLM', 'setupAI'),
    ];
    const onboardingActions: ChatMessageAction[] = [
        buildQuickActionAction('tool-help-onboarding', 'Onboarding', 'showOnboarding'),
        buildQuickActionAction('tool-help-configure-llm', 'Configure LLM', 'setupAI'),
        buildQuickActionAction('tool-help-scan-workspace', 'Scan Workspace', 'scanFolder'),
    ];
    const scanActions: ChatMessageAction[] = [
        buildQuickActionAction('tool-help-scan-current-file', 'Scan current file', 'scanFile'),
        buildQuickActionAction('tool-help-scan-workspace', 'Scan workspace', 'scanFolder'),
        buildQuickActionAction('tool-help-create-summary', 'Create Summary', 'scanSummaryReport'),
    ];

    return {
        content: lines.join('\n'),
        actions: onboardingFocused
            ? onboardingActions
            : setupFocused
                ? setupActions
                : reportFocused
                    ? reportActions
                    : scanFocused
                        ? scanActions
                        : undefined,
    };
}

function findTopFindingInCalibrationRecords(records?: StoredScanRecord[]): Finding | undefined {
    if (!Array.isArray(records) || !records.length) {
        return undefined;
    }

    return records
        .flatMap(record => record?.result?.findings ?? [])
        .filter((finding): finding is Finding => Boolean(finding && typeof finding.line === 'number'))
        .slice()
        .sort((left, right) => riskRank(right) - riskRank(left))[0];
}

function buildScoreBreakdown(result: ScanResult): string {
    if (!result.findings.length) {
        return `No findings were reported by ${buildProviderModelLabel(result)}, so the file risk score for this scan is 0.0. This is provider/model-scoped, not proof of absence across other models or deeper review.`;
    }

    const parts = result.findings
        .slice()
        .sort((left, right) => riskRank(right) - riskRank(left))
        .map(finding => `${finding.title} (${finding.riskScore ?? 'n/a'}/10)`);

    return `File risk score follows the highest remaining finding risk. Current ranking: ${parts.join(', ')}.`;
}

function buildProviderModelLabel(result: ScanResult): string {
    const provider = result.provider || 'the active provider';
    const model = result.model || 'the active model';
    return `${provider} / ${model}`;
}

function buildCleanScanScopeNote(result: ScanResult): string {
    return `Clean result scope: no findings were reported by ${buildProviderModelLabel(result)} for this scan; treat that as provider/model evidence, not a guarantee that no vulnerability exists.`;
}

function summarizeEngineEvidence(findings: Finding[]): string {
    if (!findings.length) {
        return 'Engine evidence: No findings to prove.';
    }

    const withContracts = findings.filter(finding => finding.evidenceContract);
    const confirmed = withContracts.filter(finding => finding.evidenceContract?.verdict === 'confirmed');
    const missingGuards = withContracts.filter(finding => finding.evidenceContract?.guard?.status === 'missing');
    const deterministicWithoutContract = findings.filter(finding => finding.provenance === 'deterministic' && !finding.evidenceContract);
    const aiWithoutContract = findings.filter(finding => finding.provenance !== 'deterministic' && !finding.evidenceContract);

    return [
        `Engine evidence: Structured contracts: ${withContracts.length}/${findings.length}`,
        `confirmed: ${confirmed.length}`,
        `missing guards: ${missingGuards.length}`,
        `deterministic gaps: ${deterministicWithoutContract.length}`,
        `AI without contract: ${aiWithoutContract.length}`,
    ].join(' | ');
}

function formatProviderDisagreementProof(proof: ProviderDisagreementProof): string {
    const parts = [
        proof.reason,
        proof.issueType ? `issue ${proof.issueType}` : '',
        proof.source ? `source \`${proof.source}\`` : '',
        proof.sink ? `sink \`${proof.sink}\`` : '',
        proof.guard ? `guard ${proof.guard}` : '',
    ].filter(Boolean).join(' | ');
    return `Proof pass: ${proof.verdict}${parts ? ` - ${parts}` : ''}`;
}

export function buildGroundedRemediationHighlights(findings: Finding[], maxFindings = 2): string[] {
    return findings
        .slice()
        .sort((left, right) => riskRank(right) - riskRank(left))
        .slice(0, maxFindings)
        .map(finding => {
            const remediation = resolveRemediationForFinding(finding);
            const frameworkNote = remediation.frameworkVariant
                ? ` [${remediation.frameworkVariant.framework}] ${remediation.frameworkVariant.summary}`
                : '';
            return `${finding.title}: ${remediation.remediation}${frameworkNote}`;
        });
}

function buildScanSummaryLines(result: ScanResult): string[] {
    const remediationHighlights = buildGroundedRemediationHighlights(result.findings);
    const topRiskFinding = result.findings
        .slice()
        .sort((left, right) => riskRank(right) - riskRank(left))[0];
    return [
        `File risk score: ${result.score.toFixed(1)}/10`,
        `Findings: ${result.findings.length}`,
        `Analysis mode: ${getScanTierDisplayLabel(getPrimaryScanTierLabel(result.findings))}`,
        `Analysis mix: ${summarizeScanTierCounts(result.findings)}`,
        summarizeEngineEvidence(result.findings),
        `Project context: ${result.projectContextSummary && result.projectContextSummary !== 'none' ? result.projectContextSummary : 'none'}`,
        topRiskFinding
            ? `Top issue: ${topRiskFinding.title} | via ${getScanTierDisplayLabel(getScanTierLabel(topRiskFinding))} | impact ${topRiskFinding.severity} | likelihood ${getFindingLikelihood(topRiskFinding)} | finding risk ${topRiskFinding.riskScore ?? 'n/a'}/10`
            : 'Top issue: none',
        summarizeIssueFamilies(result.findings),
        `Model: ${result.model}`,
        ...(remediationHighlights.length
            ? remediationHighlights.map((line, index) => `Remediation ${index + 1}: ${line}`)
            : []),
        !result.findings.length ? buildCleanScanScopeNote(result) : '',
        (result.warnings ?? []).length
            ? `Warnings: ${(result.warnings ?? []).join(' | ')}`
            : 'No scan warnings were reported.',
        `Summary: ${result.summary || 'No summary returned.'}`,
    ].filter(Boolean);
}

function buildProviderFailureMessage(error: unknown): string {
    const message = String((error as any)?.message ?? error ?? '').trim();
    if (isRateLimitError(error)) {
        return 'The provider hit a rate limit before it could finish that request.';
    }

    return message
        ? `The provider could not finish that request (${message}).`
        : 'The provider could not finish that request.';
}

function buildMultiFileScanResponse(
    label: string,
    completed: number,
    results: Array<{ result: ScanResult }>,
    errors: unknown[],
    topActionable?: { finding: Finding; targetPath?: string },
    reportPath?: string,
): string {
    const findings = results.flatMap(item => item.result.findings ?? []);
    const warnings = results.reduce((total, item) => total + (item.result.warnings?.length ?? 0), 0);
    const averageScore = completed > 0
        ? results.reduce((total, item) => total + (item.result.score ?? 0), 0) / completed
        : 0;
    const issueFamilies = summarizeIssueFamilies(findings);

    return [
        `${label} completed.`,
        `Files scanned: ${completed}`,
        `Total findings: ${findings.length}`,
        `Average file risk score: ${averageScore.toFixed(1)}/10`,
        summarizeEngineEvidence(findings),
        issueFamilies,
        ...buildGroundedRemediationHighlights(findings).map((line, index) => `Remediation ${index + 1}: ${line}`),
        topActionable ? `Next step: Preview fix opens a side-by-side diff for ${path.basename(topActionable.targetPath ?? 'the top finding file')}.` : '',
        reportPath ? `Report: ${reportPath}` : '',
        warnings ? `Scan warnings: ${warnings}` : 'No scan warnings were reported.',
        errors.length ? `Scan errors: ${errors.length}` : 'No scan errors were reported.',
    ].filter(Boolean).join('\n');
}

function buildCalibrationRecords(results: Array<{ uri: vscode.Uri; result: ScanResult }>): StoredScanRecord[] {
    return results.map(item => ({
        scanId: item.result.scanId,
        result: item.result,
        targetLabel: vscode.workspace.asRelativePath(item.uri, false),
        scannedAt: new Date().toISOString(),
    }));
}

function buildExplainScoreAction(id: string, results: Array<{ uri: vscode.Uri; result: ScanResult }>): ChatMessageAction {
    return {
        id,
        label: 'Explain score',
        kind: 'explainScore',
        calibrationRecords: buildCalibrationRecords(results),
    };
}

function buildLatestReportPromptContext(storage: vscode.Memento): EditorContext | undefined {
    const raw = storage.get<any>(LAST_REPORT_SNAPSHOT_KEY);
    if (!raw?.results?.length) {
        return undefined;
    }

    const results = Array.isArray(raw.results) ? raw.results : [];
    const findings = results.flatMap((item: any) => item?.result?.findings ?? []);
    const topFindings = findings
        .slice()
        .sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))
        .slice(0, 3);

    const summary = `Latest report: ${raw.targetLabel ?? 'unknown target'} with ${findings.length} finding(s) across ${results.length} file(s)`;
    const details = [
        `Latest report target: ${raw.targetLabel ?? 'unknown'}`,
        `Latest report files scanned: ${results.length}`,
        `Latest report findings: ${findings.length}`,
        ...topFindings.map((finding: Finding, index: number) =>
            `Finding ${index + 1}: ${finding.canonicalTitle || finding.title} at line ${finding.line} | severity ${finding.severity} | explanation ${finding.explanation} | fix ${finding.fix || 'none provided'}`
        ),
    ];

    return {
        summary,
        promptContext: details.join('\n'),
    };
}

export function buildFindingPromptContext(finding: Finding, snippet?: string): string {
    const remediation = resolveRemediationForFinding(finding);
    const snippetConsistencyNote = buildSnippetConsistencyNote(finding, snippet);
    return [
        'Finding selected for discussion:',
        `Title: ${finding.canonicalTitle || finding.title}`,
        `Rule: ${finding.ruleCode || 'n/a'}`,
        `Provenance: ${finding.provenance ?? 'unknown'}`,
        `Scan tier: ${getScanTierLabel(finding)}`,
        `Location: line ${finding.line}${finding.lineEnd && finding.lineEnd !== finding.line ? `-${finding.lineEnd}` : ''}`,
        `Impact: ${finding.severity}`,
        `Likelihood: ${getFindingLikelihood(finding)}`,
        `Risk: ${finding.riskScore ?? 'n/a'}/10`,
        `Why it matters: ${finding.explanation || 'No explanation provided.'}`,
        `Suggested remediation: ${remediation.remediation}`,
        remediation.recommendedActions.length
            ? `Recommended steps: ${remediation.recommendedActions.join(' | ')}`
            : '',
        remediation.frameworkVariant
            ? `Framework-specific guidance: ${remediation.frameworkVariant.framework} | ${remediation.frameworkVariant.summary}`
            : '',
        remediation.validationSteps.length
            ? `Validate with: ${remediation.validationSteps.join(' | ')}`
            : '',
        remediation.unsafeAlternatives.length
            ? `Avoid: ${remediation.unsafeAlternatives.join(' | ')}`
            : '',
        remediation.cheatSheetGuidance.length
            ? `Canonical grounding: ${remediation.cheatSheetGuidance.join(' || ')}`
            : '',
        (finding.likelihoodReasons ?? []).length
            ? `Likelihood reasons: ${(finding.likelihoodReasons ?? []).join(' | ')}`
            : '',
        snippet ? `Local code snippet:\n${snippet}` : 'Local code snippet: unavailable',
        snippetConsistencyNote ? `Code/finding note: ${snippetConsistencyNote}` : '',
        'Help the user understand the issue in plain language, explain why the fix works, and show a safe replacement approach grounded in this finding.',
    ].filter(Boolean).join('\n');
}

function buildSnippetConsistencyNote(finding: Finding, snippet?: string): string | undefined {
    if (!snippet) {
        return undefined;
    }

    const title = `${finding.canonicalTitle || finding.title} ${finding.ruleCode || ''}`.toLowerCase();
    const normalizedSnippet = snippet.toLowerCase();
    const mentionsDeserialization = /deserial|pickle|unsafe loader/.test(title);
    const usesJsonLoads = /json\.loads\s*\(/.test(normalizedSnippet);
    const usesPickle = /pickle\.loads?\s*\(/.test(normalizedSnippet);

    if (mentionsDeserialization && usesJsonLoads && !usesPickle) {
        return 'The visible snippet shows json.loads(...) rather than pickle.loads(...). Call out that mismatch explicitly and avoid describing pickle-based code execution unless other grounded context proves it.';
    }

    return undefined;
}

function extractNearbyContextSources(context?: string): string[] {
    if (!context) {
        return [];
    }

    return context
        .split(/\r?\n/)
        .filter(line => line.startsWith('Nearby context file: '))
        .map(line => line.replace('Nearby context file: ', '').trim())
        .filter(Boolean);
}

export function buildFindingContextSummary(options: {
    finding: Finding;
    hasActiveSnippet: boolean;
    nearbyContext?: string;
    hasLatestReportContext: boolean;
    groundedFrameworks?: string[];
    groundedCheatSheets?: string[];
}): string {
    const sources: string[] = [];
    if (options.hasActiveSnippet) {
        sources.push('- Active file snippet around the finding');
    }

    const nearbyFiles = extractNearbyContextSources(options.nearbyContext);
    for (const file of nearbyFiles) {
        sources.push(`- Nearby file: ${file}`);
    }

    if (options.hasLatestReportContext) {
        sources.push('- Latest report summary context');
    }

    if (options.groundedFrameworks?.length) {
        sources.push(`- Curated framework pack: ${options.groundedFrameworks.join(', ')}`);
    }

    if (options.groundedCheatSheets?.length) {
        sources.push(`- Curated cheat-sheet pack: ${options.groundedCheatSheets.join(', ')}`);
    }

    return [
        `Context sources used for "${options.finding.canonicalTitle || options.finding.title}":`,
        ...(sources.length ? sources : ['- Finding metadata only']),
    ].join('\n');
}

export function extractPatchedFileContent(raw: string, originalText: string): string {
    const trimmed = raw.trim();
    const fenced = trimmed.match(/^```[a-zA-Z0-9_-]*\r?\n([\s\S]*?)\r?\n```$/);
    if (fenced?.[1]) {
        return fenced[1];
    }

    return trimmed || originalText;
}

function countChangedLines(originalText: string, patchedText: string): { changedLines: number; totalLines: number } {
    const originalLines = originalText.split(/\r?\n/);
    const patchedLines = patchedText.split(/\r?\n/);
    const totalLines = Math.max(originalLines.length, patchedLines.length, 1);
    let changedLines = 0;

    for (let index = 0; index < totalLines; index += 1) {
        if ((originalLines[index] ?? '') !== (patchedLines[index] ?? '')) {
            changedLines += 1;
        }
    }

    return { changedLines, totalLines };
}

function looksLikeMalformedFixResponse(raw: string): boolean {
    const trimmed = raw.trim();
    return trimmed.includes('```') && !/^```[a-zA-Z0-9_-]*\r?\n[\s\S]*\r?\n```$/.test(trimmed);
}

function validateFixPreviewContent(options: {
    raw: string;
    originalText: string;
    patchedText: string;
    finding: Finding;
    targetPath: string;
}): string | undefined {
    if (looksLikeMalformedFixResponse(options.raw)) {
        return 'Owlvex received malformed code fences from the model. Ask "fix code" to regenerate the preview.';
    }

    if (!hasMeaningfulPreviewChange(options.originalText, options.patchedText)) {
        return 'Owlvex could not produce a meaningful code diff. Ask "fix code" to regenerate the preview.';
    }

    const { changedLines, totalLines } = countChangedLines(options.originalText, options.patchedText);
    if (totalLines >= MAX_REWRITE_LINE_THRESHOLD && (changedLines / totalLines) > MAX_SINGLE_FILE_REWRITE_RATIO) {
        return `Owlvex rejected the preview for ${vscode.workspace.asRelativePath(vscode.Uri.file(options.targetPath), false)} because it rewrote too much of the file for a finding-anchored fix. Ask "fix code" to regenerate a smaller patch.`;
    }

    return undefined;
}

function validateBroadFixPreviewContent(options: {
    raw: string;
    originalText: string;
    patchedText: string;
}): string | undefined {
    if (looksLikeMalformedFixResponse(options.raw)) {
        return 'Owlvex received malformed code fences from the model. Ask "fix code" to regenerate the preview.';
    }

    if (!hasMeaningfulPreviewChange(options.originalText, options.patchedText)) {
        return 'Owlvex could not produce a meaningful code diff. Ask "fix code" to regenerate the preview.';
    }

    return undefined;
}

function validateBatchFixScope(items: ActionableFindingTarget[]): string | undefined {
    const distinctPaths = [...new Set(items.map(item => item.targetPath).filter((value): value is string => Boolean(value)))];
    if (!distinctPaths.length) {
        return 'Owlvex could not determine any actionable files for the combined fix preview.';
    }
    return undefined;
}

function inferSyntaxValidity(
    targetPath: string,
    patchedText: string,
    rescanned?: ScanResult,
): boolean | null {
    const warnings = rescanned?.warnings ?? [];
    if (warnings.some(warning => /\b(parse|syntax|unexpected token|compile|compilation)\b/i.test(warning))) {
        return false;
    }

    const ext = path.extname(targetPath).toLowerCase();
    if (ext === '.json') {
        try {
            JSON.parse(patchedText);
            return true;
        } catch {
            return false;
        }
    }

    if (ext === '.js' || ext === '.cjs') {
        if (/\b(import|export)\b/.test(patchedText)) {
            return null;
        }
        try {
            // Parse-only validation for CommonJS-style JavaScript.
            // eslint-disable-next-line no-new-func
            new Function(patchedText);
            return true;
        } catch {
            return false;
        }
    }

    return rescanned ? true : null;
}

function extractLocalImports(source: string): ImportedSymbolContext[] {
    const contexts = new Map<string, Set<string>>();

    const importMatches = source.matchAll(/import\s+([\s\S]*?)\s+from\s+['"](\.[^'"]+)['"]/g);
    for (const match of importMatches) {
        const clause = match[1]?.trim() ?? '';
        const specifier = match[2]?.trim();
        if (!specifier) {
            continue;
        }

        const names = contexts.get(specifier) ?? new Set<string>();
        const defaultMatch = clause.match(/^([A-Za-z_$][\w$]*)/);
        if (defaultMatch?.[1] && !defaultMatch[1].startsWith('{') && defaultMatch[1] !== '*') {
            names.add(defaultMatch[1]);
        }

        const namedGroup = clause.match(/\{([^}]+)\}/);
        if (namedGroup?.[1]) {
            for (const part of namedGroup[1].split(',')) {
                const token = part.trim();
                if (!token) {
                    continue;
                }
                const alias = token.split(/\s+as\s+/i).pop()?.trim();
                if (alias) {
                    names.add(alias);
                }
            }
        }

        contexts.set(specifier, names);
    }

    const requireMatches = source.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](\.[^'"]+)['"]\s*\)/g);
    for (const match of requireMatches) {
        const localName = match[1]?.trim();
        const specifier = match[2]?.trim();
        if (!localName || !specifier) {
            continue;
        }
        const names = contexts.get(specifier) ?? new Set<string>();
        names.add(localName);
        contexts.set(specifier, names);
    }

    return [...contexts.entries()].map(([specifier, names]) => ({
        specifier,
        importedNames: [...names],
    }));
}

async function tryReadWorkspaceFile(uri: vscode.Uri): Promise<string | undefined> {
    try {
        const raw = await vscode.workspace.fs.readFile(uri);
        return Buffer.from(raw).toString('utf8');
    } catch {
        return undefined;
    }
}

interface WorkspaceFolderMatch {
    uri: vscode.Uri;
    label: string;
    score: number;
}

interface RepoScopeRoot {
    uri: vscode.Uri;
    label: string;
}

function buildWorkspacePathTokenSet(prompt: string): Set<string> {
    const normalized = prompt
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .split(/\s+/)
        .map(token => token.trim())
        .filter(token => token.length >= 3)
        .filter(token => !new Set([
            'what', 'does', 'this', 'that', 'suppose', 'supposed', 'should', 'would', 'could', 'repo', 'repository',
            'workspace', 'project', 'folder', 'directory', 'module', 'application', 'app', 'work', 'doing', 'explain',
            'tell', 'about', 'with', 'from', 'into', 'general',
        ]).has(token));

    return new Set(normalized);
}

function scoreWorkspacePathLabel(prompt: string, promptTokens: Set<string>, label: string): number {
    if (!promptTokens.size) {
        return 0;
    }

    const normalizedPrompt = prompt.toLowerCase();
    const normalizedLabel = normalizeToken(label.replace(/[\\/]+/g, ' '));
    let score = 0;
    for (const token of promptTokens) {
        const normalizedToken = normalizeToken(token);
        if (!normalizedToken) {
            continue;
        }
        if (normalizedLabel === normalizedToken) {
            score += 10;
        } else if (normalizedLabel.includes(normalizedToken)) {
            score += 6;
        }
    }

    if (normalizedPrompt.includes(' app') || normalizedPrompt.endsWith('app') || normalizedPrompt.includes(' application')) {
        if (/(^|[\\/.-])app($|[\\/.-])/.test(label.toLowerCase())) {
            score += 4;
        }
    }

    const leafName = label.split(/[\\/]+/g).pop()?.toLowerCase() ?? '';
    if (new Set(['src', 'lib', 'app', 'routes', 'controllers', 'services']).has(leafName)) {
        score -= 3;
    }

    return score;
}

async function collectWorkspaceDirectoryCandidates(
    folder: RepoScopeRoot,
    prompt: string,
    maxDepth = 3,
): Promise<WorkspaceFolderMatch[]> {
    const promptTokens = buildWorkspacePathTokenSet(prompt);
    if (!promptTokens.size) {
        return [];
    }

    const queue: Array<{ uri: vscode.Uri; relativePath: string; depth: number }> = [{ uri: folder.uri, relativePath: '', depth: 0 }];
    const results: WorkspaceFolderMatch[] = [];
    const skippedNames = new Set(['node_modules', 'dist', 'build', 'coverage', '.git', '.owlvex', 'tmp-layne']);

    while (queue.length) {
        const current = queue.shift()!;
        let entries: Array<[string, vscode.FileType]> = [];
        try {
            entries = await vscode.workspace.fs.readDirectory(current.uri);
        } catch {
            continue;
        }

        for (const [name, fileType] of entries) {
            if (fileType !== vscode.FileType.Directory || name.startsWith('.') || skippedNames.has(name)) {
                continue;
            }

            const childRelativePath = current.relativePath ? `${current.relativePath}/${name}` : name;
            const childUri = vscode.Uri.joinPath(current.uri, name);
            const score = scoreWorkspacePathLabel(prompt, promptTokens, childRelativePath);
            if (score > 0) {
                results.push({
                    uri: childUri,
                    label: childRelativePath,
                    score,
                });
            }

            if (current.depth + 1 < maxDepth) {
                queue.push({
                    uri: childUri,
                    relativePath: childRelativePath,
                    depth: current.depth + 1,
                });
            }
        }
    }

    return results.sort((left, right) => right.score - left.score || left.label.localeCompare(right.label));
}

async function resolveLocalImportUri(baseFile: vscode.Uri, specifier: string): Promise<vscode.Uri | undefined> {
    const baseDir = path.dirname(baseFile.fsPath);
    const resolvedBase = path.resolve(baseDir, specifier);
    const explicitExt = path.extname(resolvedBase);
    const candidates = explicitExt
        ? [resolvedBase]
        : [
            ...CONTEXT_EXTENSIONS.map(ext => `${resolvedBase}${ext}`),
            ...CONTEXT_EXTENSIONS.map(ext => path.join(resolvedBase, `index${ext}`)),
        ];

    for (const candidate of candidates) {
        const uri = vscode.Uri.file(candidate);
        const content = await tryReadWorkspaceFile(uri);
        if (content !== undefined) {
            return uri;
        }
    }

    return undefined;
}

function buildExcerpt(content: string, maxLines = 20): string {
    return content
        .split(/\r?\n/)
        .slice(0, maxLines)
        .map((text, index) => `${String(index + 1).padStart(4, ' ')} | ${text}`)
        .join('\n');
}

export async function buildNearbyProjectContext(
    document: vscode.TextDocument,
    finding?: Pick<Finding, 'line' | 'lineEnd'>,
    maxFiles = 2,
): Promise<string | undefined> {
    const source = document.getText();
    const imports = extractLocalImports(source);
    if (!imports.length) {
        return undefined;
    }

    const allLines = source.split(/\r?\n/);
    const relevantStart = Math.max(0, (finding?.line ?? 1) - 4);
    const relevantEnd = Math.min(allLines.length, Math.max(finding?.lineEnd ?? finding?.line ?? 1, finding?.line ?? 1) + 3);
    const relevantWindow = allLines
        .slice(relevantStart, relevantEnd)
        .filter(line => !/^\s*(import\b|const\s+.+?=\s*require\()/.test(line))
        .join('\n');
    const rankedImports = imports
        .map(item => ({
            ...item,
            score: item.importedNames.reduce((total, name) => total + (new RegExp(`\\b${name}\\b`).test(relevantWindow) ? 10 : 0), 0),
        }))
        .sort((left, right) => right.score - left.score || left.specifier.localeCompare(right.specifier));

    const collected: string[] = [];
    for (const item of rankedImports.slice(0, 6)) {
        if (collected.length >= maxFiles) {
            break;
        }

        const uri = await resolveLocalImportUri(document.uri, item.specifier);
        if (!uri) {
            continue;
        }

        const content = await tryReadWorkspaceFile(uri);
        if (!content) {
            continue;
        }

        const relative = vscode.workspace.asRelativePath(uri, false);
        collected.push(
            [
                `Nearby context file: ${relative}`,
                `Imported via: ${item.specifier}`,
                item.importedNames.length ? `Referenced symbols: ${item.importedNames.join(', ')}` : '',
                buildExcerpt(content),
            ].join('\n'),
        );
    }

    if (!collected.length) {
        return undefined;
    }

    return [
        'Nearby project context:',
        finding ? `Context prioritized around finding lines ${finding.line}${finding.lineEnd && finding.lineEnd !== finding.line ? `-${finding.lineEnd}` : ''}.` : '',
        ...collected,
        'Use these nearby files only when they materially improve the explanation or remediation. Say when the answer depends on cross-file context.',
    ].join('\n\n');
}

function severityRank(severity: string): number {
    switch (severity) {
        case 'CRITICAL':
            return 4;
        case 'HIGH':
            return 3;
        case 'MEDIUM':
            return 2;
        case 'LOW':
            return 1;
        default:
            return 0;
    }
}

function buildReviewFixAction(finding: Finding, targetPath?: string): ChatMessageAction {
    return {
        id: `generate-fix-preview-${finding.id ?? finding.line}`,
        label: 'Preview fix',
        kind: 'generateFixPreview',
        finding,
        path: targetPath,
    };
}

function buildBatchReviewFixAction(items: ActionableFindingTarget[]): ChatMessageAction | undefined {
    if (!items.length) {
        return undefined;
    }

    return {
        id: 'generate-batch-fix-preview',
        label: 'Preview fixes',
        kind: 'generateBatchFixPreview',
        findings: items,
    };
}

function buildPendingFixPreviewActions(): ChatMessageAction[] {
    return [
        {
            id: 'apply-fix-preview',
            label: 'Keep fix',
            kind: 'applyFixPreview',
        },
        {
            id: 'discard-fix-preview',
            label: 'Discard fix',
            kind: 'discardFixPreview',
        },
    ];
}

function buildActiveFixPreviewActions(options: {
    finding?: Finding;
    targetPath?: string;
    items?: ActionableFindingTarget[];
}): ChatMessageAction[] {
    const actions: ChatMessageAction[] = [];
    const batchAction = options.items?.length ? buildBatchReviewFixAction(options.items) : undefined;
    const singleAction = options.finding ? buildReviewFixAction(options.finding, options.targetPath) : undefined;
    const regenerateAction = singleAction ?? batchAction;
    if (regenerateAction) {
        actions.push({
            ...regenerateAction,
            id: `${regenerateAction.id}-retry`,
            label: 'Regenerate diff',
        });
    }

    return [...actions, ...buildPendingFixPreviewActions()];
}

function buildQuickActionAction(id: string, label: string, quickAction: string): ChatMessageAction {
    return {
        id,
        label,
        kind: 'quickAction',
        quickAction,
    };
}

function buildPostFixVerificationActions(options: {
    rescanned?: ScanResult;
    targetPath: string;
    originalFinding: Finding;
    matchingFinding?: Finding;
    nextFinding?: Finding;
}): ChatMessageAction[] {
    const actions: ChatMessageAction[] = [
        buildQuickActionAction('post-fix-scan-file', 'Scan current file', 'scanFile'),
        buildQuickActionAction('post-fix-scan-workspace', 'Scan workspace', 'scanFolder'),
    ];

    if (options.rescanned) {
        actions.unshift(buildExplainScoreAction('post-fix-explain-score', [{
            uri: vscode.Uri.file(options.targetPath),
            result: options.rescanned,
        }]));
    }

    if (options.matchingFinding) {
        actions.unshift({
            ...buildReviewFixAction(options.originalFinding, options.targetPath),
            id: 'post-fix-regenerate-diff',
            label: 'Regenerate diff',
        });
    }

    if (options.nextFinding) {
        actions.unshift({
            ...buildReviewFixAction(options.nextFinding, options.targetPath),
            id: 'post-fix-preview-next-finding',
            label: 'Preview next fix',
        });
    }

    return actions;
}

function getTopRemainingFinding(rescanned: ScanResult): Finding | undefined {
    return rescanned.findings
        .slice()
        .sort((left, right) => riskRank(right) - riskRank(left))[0];
}

function buildTargetRemovedVerificationMessage(targetUri: vscode.Uri, rescanned: ScanResult): string {
    const remainingFinding = getTopRemainingFinding(rescanned);
    const fileLabel = vscode.workspace.asRelativePath(targetUri, false);
    const lines = [
        `Verification complete: the reviewed finding is no longer present in ${fileLabel}.`,
        `Verification provider/model: ${buildProviderModelLabel(rescanned)}.`,
        `Remaining findings reported by this verification scan: ${rescanned.findings.length}. File risk is now ${rescanned.score.toFixed(1)}/10.`,
    ];

    if (remainingFinding) {
        lines.push(
            `File is not clean yet. Next remaining issue: ${remainingFinding.canonicalTitle || remainingFinding.title} (${remainingFinding.riskScore ?? 'n/a'}/10 risk) at line ${remainingFinding.line}.`,
            `What to change next: ${remainingFinding.fix || resolveRemediationForFinding(remainingFinding).remediation}`,
        );
    } else {
        lines.push(buildCleanScanScopeNote(rescanned));
    }

    return lines.filter(Boolean).join('\n');
}

function hasMeaningfulPreviewChange(originalText: string, patchedText: string): boolean {
    return Boolean(patchedText.trim()) && patchedText !== originalText;
}

function buildPendingFixPreviewMessage(finding: Finding, targetPath: string): string {
    const fileLabel = vscode.workspace.asRelativePath(vscode.Uri.file(targetPath), false);
    const findingLabel = finding.canonicalTitle || finding.title;
    return [
        `Fix preview ready for ${fileLabel}.`,
        `Reviewing: ${findingLabel} at line ${finding.line}.`,
        'A side-by-side diff is open now.',
        'The original file has not changed yet.',
        'Choose Keep fix to write the reviewed code into the file, or Discard fix to leave the file exactly as it was.',
    ].join('\n');
}

function buildBatchPendingFixPreviewMessage(changes: NonNullable<PendingFixPreview['changes']>): string {
    const fileCount = changes.length;
    const labels = changes.slice(0, 3).map(change => vscode.workspace.asRelativePath(vscode.Uri.file(change.targetPath), false));
    return [
        `Fix preview ready for ${fileCount} ${fileCount === 1 ? 'file' : 'files'}.`,
        `Files in review: ${labels.join(', ')}${fileCount > labels.length ? ', ...' : ''}`,
        'A combined diff is open now.',
        'No original files have changed yet.',
        'Choose Keep fix to write the reviewed code into the affected files, or Discard fix to leave every file exactly as it was.',
    ].join('\n');
}

function buildConversationStatus(options: {
    pendingFixPreview?: PendingFixPreview;
    latestActionableFinding?: Finding;
    latestActionableTargetPath?: string;
}): string {
    if (options.pendingFixPreview) {
        const finding = options.pendingFixPreview.finding;
        const fileLabel = vscode.workspace.asRelativePath(vscode.Uri.file(options.pendingFixPreview.targetPath), false);
        return `Reviewing fix preview: ${finding.canonicalTitle || finding.title} in ${fileLabel}.`;
    }

    if (options.latestActionableFinding) {
        const finding = options.latestActionableFinding;
        const fileLabel = options.latestActionableTargetPath
            ? vscode.workspace.asRelativePath(vscode.Uri.file(options.latestActionableTargetPath), false)
            : 'the current target file';
        return `Focused on finding: ${finding.canonicalTitle || finding.title} in ${fileLabel}.`;
    }

    return 'Conversation. Ask follow-up questions, open a fix preview, or keep working from the latest finding.';
}

function buildCombinedPreviewContent(changes: Array<{ targetPath: string; text: string }>): string {
    return changes.map(change => {
        const fileLabel = vscode.workspace.asRelativePath(vscode.Uri.file(change.targetPath), false);
        return [
            `===== ${fileLabel} =====`,
            change.text,
            '',
        ].join('\n');
    }).join('\n');
}

function getTopActionableFindingResult(
    items: Array<{ uri?: vscode.Uri; result?: ScanResult }>,
): { finding: Finding; targetPath?: string } | undefined {
    return getActionableFindingResults(items, 1)[0];
}

function getActionableFindingResults(
    items: Array<{ uri?: vscode.Uri; result?: ScanResult }>,
    limit?: number,
): ActionableFindingTarget[] {
    const candidates = items.flatMap(item =>
        (item.result?.findings ?? []).map(finding => ({
            finding,
            targetPath: item.uri?.fsPath,
        })),
    );

    return candidates
        .slice()
        .sort((left, right) => riskRank(right.finding) - riskRank(left.finding))
        .slice(0, typeof limit === 'number' ? limit : candidates.length);
}

function buildReviewFixActions(items: ActionableFindingTarget[]): ChatMessageAction[] {
    return items.map(item => buildReviewFixAction(item.finding, item.targetPath));
}

function buildPrimaryFixAction(items: ActionableFindingTarget[]): ChatMessageAction[] {
    if (!items.length) {
        return [];
    }

    if (items.length === 1) {
        return [buildReviewFixAction(items[0].finding, items[0].targetPath)];
    }

    const batchAction = buildBatchReviewFixAction(items);
    return batchAction ? [batchAction] : [];
}

function getProviderSetupHint(providerId: string): string {
    switch (providerId) {
        case 'azure-foundry':
            return 'Set the Azure endpoint, deployment name, and API key.';
        case 'custom':
            return 'Set the base URL, model name, and API key for your compatible endpoint.';
        case 'ollama':
            return 'Point Owlvex at your Ollama host and make sure the local model is installed.';
        default:
            return 'Add the API key for this provider.';
    }
}

export class ChatViewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = PROFILE.chatViewId;

    private view?: vscode.WebviewView;
    private readonly messages: ChatMessage[];
    private pendingFixPreview?: PendingFixPreview;
    private readonly restorableMessages?: ChatMessage[];
    private latestActionableFinding?: Finding;
    private latestActionableTargetPath?: string;
    private latestActionableItems: ActionableFindingTarget[] = [];
    private lastSelectedScopePaths: string[] = [];
    private readonly recentScanSnapshotsByPath = new Map<string, RecentScanSnapshot>();
    private currentMode: ConversationMode = 'general';

    constructor(
        private readonly registry: ProviderRegistry,
        private readonly storage: vscode.Memento,
        private readonly licenceMgr: Pick<LicenceManager, 'getKey' | 'getCachedInfo' | 'validate'> = {
            getKey: async () => 'test-licence',
            getCachedInfo: () => ({
                valid: true,
                licenceId: 'test-licence-id',
                teamName: 'Test Workspace',
                plan: 'free',
                seats: 1,
                seatsUsed: 1,
                features: {
                    frameworks: ['OWASP'],
                    scansPerMonth: 50,
                    promptEditor: true,
                    comparison: true,
                    teamPrompts: false,
                    ciCd: false,
                    pdfReports: false,
                    customRules: false,
                    sso: false,
                    industryPacks: [],
                    telemetryRequired: true,
                    telemetryEnabled: true,
                    telemetryOptOut: false,
                },
                usage: {
                    scansThisMonth: 0,
                    scansRemaining: 50,
                    monthlyLimitReached: false,
                },
                expiresAt: null,
            }),
            validate: async () => ({
                valid: true,
                licenceId: 'test-licence-id',
                teamName: 'Test Workspace',
                plan: 'free',
                seats: 1,
                seatsUsed: 1,
                features: {
                    frameworks: ['OWASP'],
                    scansPerMonth: 50,
                    promptEditor: true,
                    comparison: true,
                    teamPrompts: false,
                    ciCd: false,
                    pdfReports: false,
                    customRules: false,
                    sso: false,
                    industryPacks: [],
                    telemetryRequired: true,
                    telemetryEnabled: true,
                    telemetryOptOut: false,
                },
                usage: {
                    scansThisMonth: 0,
                    scansRemaining: 50,
                    monthlyLimitReached: false,
                },
                expiresAt: null,
            }),
        },
        private readonly emitUsageTelemetry: UsageTelemetryEmitter = () => {},
    ) {
        this.restorableMessages = this.getRestorableMessages();
        this.messages = buildDefaultChatMessages();
    }

    resolveWebviewView(view: vscode.WebviewView): void | Thenable<void> {
        this.view = view;
        view.webview.options = { enableScripts: true };
        view.webview.html = this.buildHtml();
        view.onDidDispose(() => {
            if (this.view === view) {
                this.view = undefined;
            }
        });

        view.webview.onDidReceiveMessage(async (message) => {
            if (message?.type === 'chat:ready') {
                this.refresh();
            }

            if (message?.type === 'chat:send') {
                await this.handleUserMessage(String(message.prompt ?? ''));
            }

            if (message?.type === 'chat:clear') {
                this.resetToFreshChat();
                void this.persistState();
                this.refresh();
            }

            if (message?.type === 'chat:restorePrevious') {
                if (this.restorableMessages?.length) {
                    this.messages.splice(0, this.messages.length, ...this.restorableMessages);
                    void this.persistState();
                    this.refresh();
                }
            }

            if (message?.type === 'chat:setProvider') {
                await this.handleSetProvider(String(message.providerId ?? ''));
            }

            if (message?.type === 'chat:setModel') {
                await this.handleSetModel(String(message.model ?? ''));
            }

            if (message?.type === 'chat:setWorkingScope') {
                await this.handleSetWorkingScope(String(message.scope ?? ''));
            }

            if (message?.type === 'chat:action') {
                await this.handleQuickAction(String(message.action ?? ''));
            }

            if (message?.type === 'chat:messageAction') {
                await this.handleMessageAction(Number(message.messageIndex ?? -1), String(message.actionId ?? ''));
            }
        });
    }

    async show(): Promise<void> {
        await vscode.commands.executeCommand(PROFILE.commands.chatFocus);
    }

    setLastScanTarget(value: string): void {
        void this.storage.update(LAST_SCAN_TARGET_KEY, value);
        this.refresh();
    }

    private getWorkingScope(): WorkingScope {
        const stored = this.storage.get<string>(WORKING_SCOPE_KEY, DEFAULT_WORKING_SCOPE);
        return isWorkingScope(stored) ? stored : DEFAULT_WORKING_SCOPE;
    }

    private async handleSetWorkingScope(scope: string): Promise<void> {
        if (!isWorkingScope(scope)) {
            return;
        }

        await this.storage.update(WORKING_SCOPE_KEY, scope);
        this.refresh();
    }

    async discussFinding(finding: Finding): Promise<void> {
        this.currentMode = 'fix';
        this.latestActionableFinding = finding;
        const discussionContext = await this.buildFindingContextBundle(finding);
        await this.show();
        this.messages.push({
            role: 'system',
            content: discussionContext.sourceSummary,
            kind: 'advisory',
            actions: discussionContext.sourceActions,
        });
        await this.handleUserMessage(
            `Discuss this finding: ${finding.canonicalTitle || finding.title} at line ${finding.line}. Explain what is wrong and how to fix it.`,
            {
                displayedPrompt: `Discuss this finding: ${finding.canonicalTitle || finding.title} at line ${finding.line}`,
                injectedContext: discussionContext.promptContext,
                suggestedFinding: finding,
            },
        );
    }

    async generateFixPreview(finding: Finding, targetPath?: string, options: GenerateFixPreviewOptions = {}): Promise<void> {
        this.currentMode = 'fix';
        this.latestActionableFinding = finding;
        this.latestActionableTargetPath = targetPath ?? this.latestActionableTargetPath;
        let document = vscode.window.activeTextEditor?.document;
        if (targetPath) {
            const targetUri = vscode.Uri.file(targetPath);
            if (!document || document.uri.fsPath !== targetUri.fsPath) {
                document = await vscode.workspace.openTextDocument(targetUri);
            }
        }

        if (!document) {
            vscode.window.showWarningMessage('Open the relevant file before generating a fix preview.');
            return;
        }

        const discussionContext = await this.buildFindingContextBundle(finding);
        await this.show();
        if (!options.reuseCurrentTurn) {
            this.messages.push({
                role: 'system',
                content: discussionContext.sourceSummary,
                kind: 'advisory',
                actions: discussionContext.sourceActions,
            });
            this.messages.push({
                role: 'user',
                content: `Preview fix: ${finding.canonicalTitle || finding.title} at line ${finding.line}`,
            });
            this.messages.push({
                role: 'assistant',
                content: 'Preparing code fix diff...',
                kind: 'advisory',
            });
        } else {
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: 'Preparing code fix diff...',
                kind: 'advisory',
            };
        }
        this.refresh();

        try {
            const provider = this.registry.getActive();
            const response = await provider.complete({
                systemPrompt: [
                    'You are Owlvex Assistant, generating a review-only code fix preview.',
                    'Return only the full updated file contents.',
                    'Do not include explanation before or after the code.',
                    'Preserve unrelated behavior and formatting where practical.',
                    'Make the smallest safe change that addresses the finding.',
                    'Do not refactor, rename, reorder, or rewrite unrelated parts of the file.',
                    'Prefer a narrow patch around the vulnerable lines unless a surrounding guard is strictly required.',
                    'Follow the grounded canonical remediation contract in the user context, including safe pattern, validation intent, and avoid guidance when relevant.',
                    'Do not introduce placeholder secrets, hardcoded keys, hardcoded tokens, disabled validation, or TODO security stubs as a fix.',
                    'If a key, secret, allowlist, issuer, or audience is required, read it from configuration or an existing trusted helper and fail closed when it is missing.',
                ].join('\n'),
                userMessage: [
                    `Generate a fix preview for this finding in the current file.`,
                    discussionContext.promptContext,
                    `Current file contents:\n${document.getText()}`,
                ].join('\n\n'),
                model: provider.selectedModel,
                temperature: 0.1,
            });

            const patched = extractPatchedFileContent(response.content || '', document.getText());
            const validationError = validateFixPreviewContent({
                raw: response.content || '',
                originalText: document.getText(),
                patchedText: patched,
                finding,
                targetPath: document.uri.fsPath,
            });
            if (validationError) {
                throw new Error(validationError);
            }

            const previewDoc = createPreviewDocumentUri(
                `${path.basename(document.uri.fsPath)}-patched`,
                patched,
            );
            await vscode.commands.executeCommand(
                'vscode.diff',
                document.uri,
                previewDoc,
                `${PROFILE.displayLabel}: Fix Preview - ${finding.canonicalTitle || finding.title}`,
            );

            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: buildPendingFixPreviewMessage(finding, document.uri.fsPath),
                kind: 'advisory',
                actions: buildActiveFixPreviewActions({
                    finding,
                    targetPath: document.uri.fsPath,
                }),
            };
            this.pendingFixPreview = {
                targetPath: document.uri.fsPath,
                originalText: document.getText(),
                patchedText: patched,
                title: finding.canonicalTitle || finding.title,
                finding,
                reviewedPaths: [document.uri.fsPath],
            };
            this.emitUsageTelemetry('fix_preview_generated', {
                outcome: 'ready',
                file_count: 1,
                canonical_id: finding.canonicalId ?? null,
                severity: finding.severity ?? null,
            });
        } catch (error: any) {
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: `Fix preview failed: ${error.message}`,
                kind: 'advisory',
                actions: [
                    buildReviewFixAction(finding, document.uri.fsPath),
                ],
            };
            this.pendingFixPreview = undefined;
            this.emitUsageTelemetry('fix_preview_generated', {
                outcome: 'failed',
                file_count: 1,
                canonical_id: finding.canonicalId ?? null,
                severity: finding.severity ?? null,
            });
        }

        void this.persistState();
        this.refresh();
    }

    async generateBatchFixPreview(items: ActionableFindingTarget[], options: GenerateFixPreviewOptions = {}): Promise<void> {
        this.currentMode = 'fix';
        const validItems = items.filter(item => item.targetPath);
        if (!validItems.length) {
            vscode.window.showWarningMessage('No actionable files were available for a combined fix preview.');
            return;
        }

        await this.show();
        if (!options.reuseCurrentTurn) {
            const targetFileCount = new Set(validItems.map(item => normalizeReviewedPath(item.targetPath!))).size;
            this.messages.push({
                role: 'user',
                content: `Preview fixes for the latest scan (${validItems.length} finding(s) across ${targetFileCount} file(s))`,
            });
            this.messages.push({
                role: 'assistant',
                content: 'Preparing broad remediation diff for the latest scan...',
                kind: 'advisory',
            });
        } else {
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: 'Preparing broad remediation diff for the latest scan...',
                kind: 'advisory',
            };
        }
        this.refresh();

        try {
            const provider = this.registry.getActive();
            const groups = new Map<string, Finding[]>();
            for (const item of validItems) {
                const targetPath = item.targetPath!;
                const list = groups.get(targetPath) ?? [];
                list.push(item.finding);
                groups.set(targetPath, list);
            }

            const batchScopeError = validateBatchFixScope(validItems);
            if (batchScopeError) {
                throw new Error(batchScopeError);
            }

            const changes: NonNullable<PendingFixPreview['changes']> = [];
            for (const [targetPath, findings] of groups.entries()) {
                const targetUri = vscode.Uri.file(targetPath);
                const document = await vscode.workspace.openTextDocument(targetUri);
                const contexts = await Promise.all(findings.map(async finding => {
                    const discussionContext = await this.buildFindingContextBundle(finding);
                    return discussionContext.promptContext;
                }));

                const response = await provider.complete({
                    systemPrompt: [
                        'You are Owlvex Assistant, generating a review-only code fix preview.',
                        'Return only the full updated file contents.',
                        'Do not include explanation before or after the code.',
                        'Preserve unrelated behavior and formatting where practical.',
                        'Make the smallest safe changes that address all listed findings in this file.',
                        'Do not refactor, rename, reorder, or rewrite unrelated parts of the file.',
                        'Keep the patch constrained to the reviewed findings and the minimum supporting validation or guard logic.',
                        'Follow the grounded canonical remediation contract in the user context, including safe pattern, validation intent, and avoid guidance when relevant.',
                        'Do not introduce placeholder secrets, hardcoded keys, hardcoded tokens, disabled validation, or TODO security stubs as a fix.',
                        'If a key, secret, allowlist, issuer, or audience is required, read it from configuration or an existing trusted helper and fail closed when it is missing.',
                    ].join('\n'),
                    userMessage: [
                        'Generate a fix preview for all of these findings in the current file.',
                        ...contexts.map((context, index) => `Finding ${index + 1}:\n${context}`),
                        `Current file contents:\n${document.getText()}`,
                    ].join('\n\n'),
                    model: provider.selectedModel,
                    temperature: 0.1,
                });

                const patched = extractPatchedFileContent(response.content || '', document.getText());
                const validationError = validateBroadFixPreviewContent({
                    raw: response.content || '',
                    originalText: document.getText(),
                    patchedText: patched,
                });
                if (validationError) {
                    throw new Error(validationError);
                }
                changes.push({
                    targetPath,
                    originalText: document.getText(),
                    patchedText: patched,
                    title: findings[0].canonicalTitle || findings[0].title,
                    finding: findings[0],
                });
            }

            const originalBundle = createPreviewDocumentUri(
                'latest-scan-original',
                buildCombinedPreviewContent(changes.map(change => ({
                    targetPath: change.targetPath,
                    text: change.originalText,
                }))),
            );
            const patchedBundle = createPreviewDocumentUri(
                'latest-scan-patched',
                buildCombinedPreviewContent(changes.map(change => ({
                    targetPath: change.targetPath,
                    text: change.patchedText,
                }))),
            );

            await vscode.commands.executeCommand(
                'vscode.diff',
                originalBundle,
                patchedBundle,
                `${PROFILE.displayLabel}: Fix Preview - Latest Scan`,
            );

            const primaryChange = changes[0];
            this.pendingFixPreview = {
                targetPath: primaryChange.targetPath,
                originalText: primaryChange.originalText,
                patchedText: primaryChange.patchedText,
                title: primaryChange.title,
                finding: primaryChange.finding,
                reviewedPaths: changes.map(change => change.targetPath),
                changes,
            };
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: buildBatchPendingFixPreviewMessage(changes),
                kind: 'advisory',
                actions: buildActiveFixPreviewActions({
                    items: validItems,
                }),
            };
            this.emitUsageTelemetry('fix_preview_generated', {
                outcome: 'ready',
                file_count: changes.length,
                canonical_id: primaryChange.finding.canonicalId ?? null,
                severity: primaryChange.finding.severity ?? null,
            });
        } catch (error: any) {
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: `Fix preview failed: ${error.message}`,
                kind: 'advisory',
                actions: buildBatchReviewFixAction(validItems)
                    ? [buildBatchReviewFixAction(validItems)!]
                    : undefined,
            };
            this.pendingFixPreview = undefined;
            this.emitUsageTelemetry('fix_preview_generated', {
                outcome: 'failed',
                file_count: validItems.length,
                canonical_id: validItems[0]?.finding.canonicalId ?? null,
                severity: validItems[0]?.finding.severity ?? null,
            });
        }

        void this.persistState();
        this.refresh();
    }

    async applyPendingFixPreview(): Promise<void> {
        this.currentMode = 'fix';
        if (!this.pendingFixPreview) {
            vscode.window.showWarningMessage('Generate a fix preview before applying one.');
            return;
        }

        const reviewedPathSet = getReviewedPathSet(this.pendingFixPreview);
        const reviewedPaths = this.pendingFixPreview.reviewedPaths?.length
            ? [...this.pendingFixPreview.reviewedPaths]
            : this.pendingFixPreview.changes?.map(change => change.targetPath) ?? [this.pendingFixPreview.targetPath];

        if ((this.pendingFixPreview.changes?.length ?? 0) > 1) {
            const changes = this.pendingFixPreview.changes!;
            const unexpectedChange = changes.find(change => !reviewedPathSet.has(normalizeReviewedPath(change.targetPath)));
            if (unexpectedChange) {
                this.messages.push({
                    role: 'assistant',
                    content: `Owlvex blocked the combined fix preview because it included an unreviewed file (${vscode.workspace.asRelativePath(vscode.Uri.file(unexpectedChange.targetPath), false)}). Regenerate the preview before applying it.`,
                    kind: 'advisory',
                });
                this.pendingFixPreview = undefined;
                void this.persistState();
                this.refresh();
                return;
            }
            for (const change of changes) {
                const document = await vscode.workspace.openTextDocument(vscode.Uri.file(change.targetPath));
                if (document.getText() !== change.originalText) {
                    this.messages.push({
                        role: 'assistant',
                        content: `One of the files changed after the combined fix preview was generated (${vscode.workspace.asRelativePath(vscode.Uri.file(change.targetPath), false)}). Regenerate the preview before applying it.`,
                        kind: 'advisory',
                    });
                    this.pendingFixPreview = undefined;
                    void this.persistState();
                    this.refresh();
                    return;
                }
            }

            const edit = new vscode.WorkspaceEdit();
            for (const change of changes) {
                edit.replace(vscode.Uri.file(change.targetPath), this.createFullDocumentRange(change.originalText), change.patchedText);
            }
            const applied = await vscode.workspace.applyEdit(edit);
            if (!applied) {
                this.messages.push({
                    role: 'assistant',
                    content: 'Owlvex could not apply the combined fix preview. The files were left unchanged.',
                    kind: 'advisory',
                });
                void this.persistState();
                this.refresh();
                return;
            }

            for (const change of changes) {
                const updatedDocument = await vscode.workspace.openTextDocument(vscode.Uri.file(change.targetPath));
                const saved = await this.saveAppliedFixDocument(updatedDocument);
                if (!saved) {
                    this.messages.push({
                        role: 'assistant',
                        content: `Owlvex applied the combined fix preview, but could not save ${vscode.workspace.asRelativePath(vscode.Uri.file(change.targetPath), false)}. Save the file, then rescan.`,
                        kind: 'advisory',
                    });
                    this.pendingFixPreview = undefined;
                    void this.persistState();
                    this.refresh();
                    return;
                }
            }

            this.messages.push({
                role: 'assistant',
                content: `Kept the reviewed fix across ${changes.length} files. The reviewed code was written into each file from the combined diff.`,
                kind: 'advisory',
                actions: [
                    buildQuickActionAction('multi-fix-scan-workspace', 'Scan workspace', 'scanFolder'),
                    buildQuickActionAction('multi-fix-review-scores', 'Review scores', 'reviewRiskCalibration'),
                ],
            });
            this.emitUsageTelemetry('fix_preview_applied', {
                outcome: 'applied',
                file_count: changes.length,
                canonical_id: changes[0]?.finding.canonicalId ?? null,
                severity: changes[0]?.finding.severity ?? null,
            });
            this.pendingFixPreview = undefined;
            this.messages.push({
                role: 'assistant',
                content: `Verifying the ${changes.length} updated file${changes.length === 1 ? '' : 's'} now...`,
                kind: 'advisory',
            });
            for (const change of changes) {
                await this.verifyAppliedFixChange({
                    targetUri: vscode.Uri.file(change.targetPath),
                    originalFinding: change.finding,
                    reviewedPaths,
                    patchedText: change.patchedText,
                });
            }
            void this.persistState();
            this.refresh();
            return;
        }

        if (!reviewedPathSet.has(normalizeReviewedPath(this.pendingFixPreview.targetPath))) {
            this.messages.push({
                role: 'assistant',
                content: 'Owlvex blocked the fix preview because the reviewed file scope no longer matches the preview target. Regenerate the preview before applying it.',
                kind: 'advisory',
            });
            this.pendingFixPreview = undefined;
            void this.persistState();
            this.refresh();
            return;
        }

        const targetUri = vscode.Uri.file(this.pendingFixPreview.targetPath);
        const document = await vscode.workspace.openTextDocument(targetUri);
        const currentText = document.getText();
        if (currentText !== this.pendingFixPreview.originalText) {
            this.messages.push({
                role: 'assistant',
                content: 'The file changed after the fix preview was generated. Regenerate the preview before applying it.',
                kind: 'advisory',
            });
            this.pendingFixPreview = undefined;
            void this.persistState();
            this.refresh();
            return;
        }

        const edit = new vscode.WorkspaceEdit();
        edit.replace(targetUri, this.createFullDocumentRange(currentText), this.pendingFixPreview.patchedText);
        const applied = await vscode.workspace.applyEdit(edit);
        if (!applied) {
            this.messages.push({
                role: 'assistant',
                content: 'Owlvex could not apply the fix preview. The file was left unchanged.',
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        const updatedDocument = await vscode.workspace.openTextDocument(targetUri);
        const saved = await this.saveAppliedFixDocument(updatedDocument);
        if (!saved) {
            this.messages.push({
                role: 'assistant',
                content: `Owlvex applied the fix preview, but could not save ${vscode.workspace.asRelativePath(targetUri, false)}. Save the file, then rescan.`,
                kind: 'advisory',
            });
            this.pendingFixPreview = undefined;
            void this.persistState();
            this.refresh();
            return;
        }
        await vscode.window.showTextDocument(updatedDocument, { preview: false });
        const originalFinding = this.pendingFixPreview.finding;
        this.messages.push({
            role: 'assistant',
            content: [
                `Kept the reviewed fix for ${vscode.workspace.asRelativePath(targetUri, false)}.`,
                `Applied change: ${originalFinding.canonicalTitle || originalFinding.title} at line ${originalFinding.line}.`,
                'Verifying the updated file now...',
            ].join('\n'),
            kind: 'advisory',
        });
        this.emitUsageTelemetry('fix_preview_applied', {
            outcome: 'applied',
            file_count: 1,
            canonical_id: originalFinding.canonicalId ?? null,
            severity: originalFinding.severity ?? null,
        });
        this.pendingFixPreview = undefined;

        try {
            const scanResult = await vscode.commands.executeCommand(PROFILE.commands.scanFile, targetUri) as { status?: string; result?: ScanResult } | undefined;
            const rescanned = scanResult?.status === 'completed' ? scanResult.result : undefined;
            if (!rescanned) {
                this.messages.push({
                    role: 'assistant',
                    content: `Verification could not confirm the result for ${vscode.workspace.asRelativePath(targetUri, false)}. The reviewed code was kept, but no completed rescan result was returned.`,
                    kind: 'advisory',
                    actions: buildPostFixVerificationActions({
                        targetPath: targetUri.fsPath,
                        originalFinding,
                    }),
                });
                this.emitUsageTelemetry('fix_verification_completed', {
                    outcome: 'verification_incomplete',
                    file_count: 1,
                    canonical_id: originalFinding.canonicalId ?? null,
                    severity: originalFinding.severity ?? null,
                    risk_before: originalFinding.riskScore ?? null,
                    target_removed: false,
                });
                await this.recordFixBenchmarkResult({
                    targetUri,
                    finding: originalFinding,
                    reviewedPaths,
                    appliedCleanly: true,
                    patchedText: updatedDocument.getText(),
                    notes: 'Fix kept, but verification scan did not return a completed result.',
                });
            } else {
                const matchingFinding = rescanned.findings.find(candidate =>
                    this.isSameFindingFamily(candidate, originalFinding)
                );
                if (!matchingFinding) {
                    const providerComparisonNotes = this.buildProviderComparisonNotes([{ uri: targetUri, result: rescanned }]);
                    this.messages.push({
                        role: 'assistant',
                        content: [
                            buildTargetRemovedVerificationMessage(targetUri, rescanned),
                            ...providerComparisonNotes,
                        ].filter(Boolean).join('\n'),
                        kind: 'advisory',
                        actions: buildPostFixVerificationActions({
                            rescanned,
                            targetPath: targetUri.fsPath,
                            originalFinding,
                            nextFinding: getTopRemainingFinding(rescanned),
                        }),
                    });
                    this.emitUsageTelemetry('fix_verification_completed', {
                        outcome: 'removed',
                        file_count: 1,
                        canonical_id: originalFinding.canonicalId ?? null,
                        severity: originalFinding.severity ?? null,
                        risk_before: originalFinding.riskScore ?? null,
                        risk_after: null,
                        target_removed: true,
                    });
                } else if ((matchingFinding.riskScore ?? 0) < (originalFinding.riskScore ?? 0)) {
                    this.messages.push({
                        role: 'assistant',
                        content: `Verification complete: the finding still exists, but its risk dropped from ${originalFinding.riskScore ?? 'n/a'}/10 to ${matchingFinding.riskScore ?? 'n/a'}/10. File risk is now ${rescanned.score.toFixed(1)}/10.`,
                        kind: 'advisory',
                        actions: buildPostFixVerificationActions({
                            rescanned,
                            targetPath: targetUri.fsPath,
                            originalFinding,
                            matchingFinding,
                        }),
                    });
                    this.emitUsageTelemetry('fix_verification_completed', {
                        outcome: 'risk_reduced',
                        file_count: 1,
                        canonical_id: originalFinding.canonicalId ?? null,
                        severity: originalFinding.severity ?? null,
                        risk_before: originalFinding.riskScore ?? null,
                        risk_after: matchingFinding.riskScore ?? null,
                        target_removed: false,
                    });
                } else {
                    this.messages.push({
                        role: 'assistant',
                        content: `Verification complete: the finding is still present after the kept fix. Review the diff again or generate another fix. File risk is ${rescanned.score.toFixed(1)}/10.`,
                        kind: 'advisory',
                        actions: buildPostFixVerificationActions({
                            rescanned,
                            targetPath: targetUri.fsPath,
                            originalFinding,
                            matchingFinding,
                        }),
                    });
                    this.emitUsageTelemetry('fix_verification_completed', {
                        outcome: 'still_present',
                        file_count: 1,
                        canonical_id: originalFinding.canonicalId ?? null,
                        severity: originalFinding.severity ?? null,
                        risk_before: originalFinding.riskScore ?? null,
                        risk_after: matchingFinding.riskScore ?? null,
                        target_removed: false,
                    });
                }
                await this.recordFixBenchmarkResult({
                    targetUri,
                    finding: originalFinding,
                    reviewedPaths,
                    appliedCleanly: true,
                    patchedText: updatedDocument.getText(),
                    rescanned,
                    matchingFinding,
                    notes: matchingFinding
                        ? 'Fix kept and verification scan completed; the target finding still matched after the rescan.'
                        : 'Fix kept and verification scan completed; the target finding was no longer present.',
                });
            }
        } catch (error: any) {
            this.messages.push({
                role: 'assistant',
                content: `Verification scan failed after keeping the fix for ${vscode.workspace.asRelativePath(targetUri, false)}: ${error.message}`,
                kind: 'advisory',
                actions: buildPostFixVerificationActions({
                    targetPath: targetUri.fsPath,
                    originalFinding,
                }),
            });
            this.emitUsageTelemetry('fix_verification_completed', {
                outcome: 'verification_failed',
                file_count: 1,
                canonical_id: originalFinding.canonicalId ?? null,
                severity: originalFinding.severity ?? null,
                risk_before: originalFinding.riskScore ?? null,
                target_removed: false,
            });
            await this.recordFixBenchmarkResult({
                targetUri,
                finding: originalFinding,
                reviewedPaths,
                appliedCleanly: true,
                patchedText: updatedDocument.getText(),
                notes: `Verification scan failed: ${error.message}`,
            });
        }
        void this.persistState();
        this.refresh();
    }

    private async saveAppliedFixDocument(document: vscode.TextDocument): Promise<boolean> {
        const save = (document as vscode.TextDocument & { save?: () => Thenable<boolean> | Promise<boolean> }).save;
        if (typeof save !== 'function') {
            return true;
        }
        return Boolean(await save.call(document));
    }

    private async verifyAppliedFixChange(options: {
        targetUri: vscode.Uri;
        originalFinding: Finding;
        reviewedPaths: string[];
        patchedText: string;
    }): Promise<void> {
        const { targetUri, originalFinding, reviewedPaths, patchedText } = options;
        try {
            const scanResult = await vscode.commands.executeCommand(PROFILE.commands.scanFile, targetUri) as { status?: string; result?: ScanResult } | undefined;
            const rescanned = scanResult?.status === 'completed' ? scanResult.result : undefined;
            if (!rescanned) {
                this.messages.push({
                    role: 'assistant',
                    content: `Verification could not confirm the result for ${vscode.workspace.asRelativePath(targetUri, false)}. The reviewed code was kept, but no completed rescan result was returned.`,
                    kind: 'advisory',
                    actions: buildPostFixVerificationActions({
                        targetPath: targetUri.fsPath,
                        originalFinding,
                    }),
                });
                this.emitUsageTelemetry('fix_verification_completed', {
                    outcome: 'verification_incomplete',
                    file_count: 1,
                    canonical_id: originalFinding.canonicalId ?? null,
                    severity: originalFinding.severity ?? null,
                    risk_before: originalFinding.riskScore ?? null,
                    target_removed: false,
                });
                await this.recordFixBenchmarkResult({
                    targetUri,
                    finding: originalFinding,
                    reviewedPaths,
                    appliedCleanly: true,
                    patchedText,
                    notes: 'Fix kept, but verification scan did not return a completed result.',
                });
                return;
            }

            const matchingFinding = rescanned.findings.find(candidate =>
                this.isSameFindingFamily(candidate, originalFinding)
            );
            if (!matchingFinding) {
                const providerComparisonNotes = this.buildProviderComparisonNotes([{ uri: targetUri, result: rescanned }]);
                this.messages.push({
                    role: 'assistant',
                    content: [
                        buildTargetRemovedVerificationMessage(targetUri, rescanned),
                        ...providerComparisonNotes,
                    ].filter(Boolean).join('\n'),
                    kind: 'advisory',
                    actions: buildPostFixVerificationActions({
                        rescanned,
                        targetPath: targetUri.fsPath,
                        originalFinding,
                        nextFinding: getTopRemainingFinding(rescanned),
                    }),
                });
                this.emitUsageTelemetry('fix_verification_completed', {
                    outcome: 'removed',
                    file_count: 1,
                    canonical_id: originalFinding.canonicalId ?? null,
                    severity: originalFinding.severity ?? null,
                    risk_before: originalFinding.riskScore ?? null,
                    risk_after: null,
                    target_removed: true,
                });
            } else if ((matchingFinding.riskScore ?? 0) < (originalFinding.riskScore ?? 0)) {
                this.messages.push({
                    role: 'assistant',
                    content: `Verification complete: the finding still exists, but its risk dropped from ${originalFinding.riskScore ?? 'n/a'}/10 to ${matchingFinding.riskScore ?? 'n/a'}/10. File risk is now ${rescanned.score.toFixed(1)}/10.`,
                    kind: 'advisory',
                    actions: buildPostFixVerificationActions({
                        rescanned,
                        targetPath: targetUri.fsPath,
                        originalFinding,
                        matchingFinding,
                    }),
                });
                this.emitUsageTelemetry('fix_verification_completed', {
                    outcome: 'risk_reduced',
                    file_count: 1,
                    canonical_id: originalFinding.canonicalId ?? null,
                    severity: originalFinding.severity ?? null,
                    risk_before: originalFinding.riskScore ?? null,
                    risk_after: matchingFinding.riskScore ?? null,
                    target_removed: false,
                });
            } else {
                this.messages.push({
                    role: 'assistant',
                    content: `Verification complete: the finding is still present after the kept fix. Review the diff again or generate another fix. File risk is ${rescanned.score.toFixed(1)}/10.`,
                    kind: 'advisory',
                    actions: buildPostFixVerificationActions({
                        rescanned,
                        targetPath: targetUri.fsPath,
                        originalFinding,
                        matchingFinding,
                    }),
                });
                this.emitUsageTelemetry('fix_verification_completed', {
                    outcome: 'still_present',
                    file_count: 1,
                    canonical_id: originalFinding.canonicalId ?? null,
                    severity: originalFinding.severity ?? null,
                    risk_before: originalFinding.riskScore ?? null,
                    risk_after: matchingFinding.riskScore ?? null,
                    target_removed: false,
                });
            }

            await this.recordFixBenchmarkResult({
                targetUri,
                finding: originalFinding,
                reviewedPaths,
                appliedCleanly: true,
                patchedText,
                rescanned,
                matchingFinding,
                notes: matchingFinding
                    ? 'Fix kept and verification scan completed; the target finding still matched after the rescan.'
                    : 'Fix kept and verification scan completed; the target finding was no longer present.',
            });
        } catch (error: any) {
            this.messages.push({
                role: 'assistant',
                content: `Verification scan failed after keeping the fix for ${vscode.workspace.asRelativePath(targetUri, false)}: ${error.message}`,
                kind: 'advisory',
                actions: buildPostFixVerificationActions({
                    targetPath: targetUri.fsPath,
                    originalFinding,
                }),
            });
            this.emitUsageTelemetry('fix_verification_completed', {
                outcome: 'verification_failed',
                file_count: 1,
                canonical_id: originalFinding.canonicalId ?? null,
                severity: originalFinding.severity ?? null,
                risk_before: originalFinding.riskScore ?? null,
                target_removed: false,
            });
            await this.recordFixBenchmarkResult({
                targetUri,
                finding: originalFinding,
                reviewedPaths,
                appliedCleanly: true,
                patchedText,
                notes: `Verification scan failed: ${error.message}`,
            });
        }
    }

    private async handleUserMessage(prompt: string, options: UserPromptOptions = {}): Promise<void> {
        const trimmed = prompt.trim();
        if (!trimmed) return;

        this.messages.push({ role: 'user', content: options.displayedPrompt ?? trimmed });
        this.messages.push({ role: 'assistant', content: 'Thinking...', kind: 'advisory' });
        const hasCurrentFindingAnchor = Boolean(this.pendingFixPreview?.finding || this.latestActionableFinding);
        const canAnchorToCurrentFinding = !options.suggestedFinding && hasCurrentFindingAnchor && (
            looksLikeFixRequest(trimmed)
            || looksLikeImplementRequest(trimmed)
            || looksLikeFindingFollowUp(trimmed)
            || Boolean(this.pendingFixPreview)
        );
        const inferredMode = this.inferConversationMode(trimmed, options, canAnchorToCurrentFinding);
        this.refresh();

        try {
            const localAction = await this.tryHandleLocalAction(trimmed);
            if (localAction.handled) {
                this.currentMode = 'scan';
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    content: localAction.response || 'Completed.',
                    kind: localAction.kind
                        ?? (localAction.response?.includes('Report:') || localAction.response?.includes('Score:')
                            ? 'scan'
                            : 'advisory'),
                    actions: localAction.actions,
                };
                void this.persistState();
                this.refresh();
                return;
            }

            const activeLicence = this.licenceMgr.getCachedInfo()
                ?? await this.licenceMgr.validate(
                    vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('apiUrl', PROFILE.defaultApiUrl)
                    || PROFILE.defaultApiUrl,
                ).catch(() => null);
            if (!activeLicence || !hasAiAssistantAccess(activeLicence)) {
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    content: activeLicence
                        ? buildPlanUpgradeMessage(this.currentMode === 'fix' ? 'fix' : 'assistant')
                        : 'A valid Owlvex licence is required before AI chat, explanations, or fix previews can run. Use Free, Start Trial, or Enter Licence to continue.',
                    kind: 'advisory',
                    actions: !activeLicence
                        ? [
                            {
                                id: 'missing-licence-use-free',
                                label: 'Use Free',
                                kind: 'quickAction',
                                quickAction: 'useFree',
                            },
                            {
                                id: 'missing-licence-start-trial',
                                label: 'Start Trial',
                                kind: 'quickAction',
                                quickAction: 'startTrial',
                            },
                            {
                                id: 'missing-licence-enter-licence',
                                label: 'Enter Licence',
                                kind: 'quickAction',
                                quickAction: 'enterLicence',
                            },
                        ]
                        : undefined,
                };
                void this.persistState();
                this.refresh();
                return;
            }

            const autoSuggestedFinding = canAnchorToCurrentFinding
                ? (this.pendingFixPreview?.finding ?? this.latestActionableFinding)
                : undefined;
            const autoTargetPath = this.getActiveFixTargetPath();
            if (!options.injectedContext && !options.suggestedFinding && looksLikeImplementRequest(trimmed) && autoSuggestedFinding && autoTargetPath) {
                this.currentMode = 'fix';
                await this.generateFixPreview(autoSuggestedFinding, autoTargetPath, { reuseCurrentTurn: true });
                void this.persistState();
                this.refresh();
                return;
            }

            const provider = this.registry.getActive();
            this.currentMode = inferredMode;
            const workspaceSummary = this.getWorkspaceSummary();
            const workingScope = this.getWorkingScope();
            const editorContext = this.currentMode === 'general'
                ? { summary: 'Working context: not injected by default in General mode', promptContext: 'Working context: not injected by default in General mode.' }
                : this.currentMode === 'repo'
                    ? await this.buildRepoAwareWorkingScopeContext(workingScope, trimmed)
                    : await this.buildWorkingScopeContext(workingScope);
            const scanContext = this.currentMode === 'general'
                ? { summary: 'Scan context: not injected by default in General mode', promptContext: 'Scan context: not injected by default in General mode.' }
                : this.buildScanContext(workingScope);
            const projectContext = this.currentMode === 'general'
                ? { summary: 'none', combined: '' }
                : await loadProjectContextInfo();
            const autoInjectedContext = !options.injectedContext && autoSuggestedFinding
                ? buildFindingPromptContext(autoSuggestedFinding, this.buildActiveSnippetForFinding(autoSuggestedFinding))
                : undefined;
            const latestReportContext = this.currentMode === 'general'
                ? undefined
                : shouldUseLatestScanContext(trimmed, options)
                    ? buildLatestReportPromptContext(this.storage)
                    : undefined;
            const recentConversationContext = this.buildRecentConversationContext();

            const response = await provider.complete({
                systemPrompt: [
                    'You are Owlvex Assistant, an in-editor AI teammate focused on security and repository-level guidance.',
                    'Be concise, practical, and specific.',
                    `Interaction mode: ${getConversationModeLabel(this.currentMode)}`,
                    getConversationModeHint(this.currentMode),
                    buildToolUsageGuidance(),
                    'These chat responses are advisory guidance unless the user explicitly triggers a scan action.',
                    'When the user asks how to fix a finding, replace vulnerable code, or explain a scan result, explain the problem in plain language first and then show the safe replacement code.',
                    'When relevant, explicitly say what the current code is doing wrong, what to stop doing, and what safe pattern should replace it.',
                    'If the active file or latest scan already points to a concrete finding, ground the answer in that finding instead of answering generically.',
                    'If the visible local code snippet appears to contradict the finding label, say that explicitly before giving advice and do not claim dangerous code paths that are not shown.',
                    'Use recent conversation context to resolve short follow-ups, pronouns, locations, and references like "that app" or "weather"; do not ignore the latest user message.',
                    this.currentMode === 'general'
                        ? 'In General mode, answer as a normal assistant. Do not imply repo inspection, scan evidence, or finding posture unless the user explicitly asks for repo or security analysis.'
                        : this.currentMode === 'repo'
                        ? 'In Repo Q&A mode, explain the repo or module behavior grounded in the selected working scope and do not present the answer as a vulnerability result unless the user explicitly asks for security analysis.'
                        : this.currentMode === 'fix'
                            ? 'In Fix mode, stay anchored to the active finding or preview scope. Do not imply that a fresh scan was run unless one actually happened.'
                            : 'In Scan mode, keep the answer aligned to the scan action or scan-backed evidence already produced.',
                    ...(this.currentMode === 'general'
                        ? ['Repo grounding: off by default in General mode.']
                        : [
                            `Open workspace folders: ${workspaceSummary}`,
                            `Working scope: ${getWorkingScopeLabel(workingScope)}`,
                            scanContext.summary,
                            editorContext.summary,
                            projectContext.combined
                                ? `Project context contract available: ${projectContext.summary}`
                                : 'Project context contract: none',
                        ]),
                    autoSuggestedFinding
                        ? `Active finding for follow-up: ${autoSuggestedFinding.canonicalTitle || autoSuggestedFinding.title} at line ${autoSuggestedFinding.line}`
                        : 'Active finding for follow-up: none',
                    latestReportContext?.summary ?? 'Latest report: none',
                ].join('\n'),
                userMessage: [
                    trimmed,
                    recentConversationContext,
                    options.injectedContext ?? autoInjectedContext ?? 'Injected discussion context: none',
                    ...(this.currentMode === 'general'
                        ? ['Repo context: not injected by default in General mode.']
                        : [
                            scanContext.promptContext,
                            projectContext.combined ? `Project context contract:\n${projectContext.combined}` : 'Project context contract: none',
                            editorContext.promptContext,
                        ]),
                    latestReportContext?.promptContext ?? 'Latest report context: none',
                ].join('\n\n'),
                model: provider.selectedModel,
                temperature: 0.2,
            });

            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                content: response.content || 'No response returned.',
                kind: 'advisory',
                actions: this.buildFixFollowUpActions(trimmed, options.suggestedFinding ?? autoSuggestedFinding),
            };
        } catch (error: any) {
            const fallbackFinding = options.suggestedFinding ?? this.pendingFixPreview?.finding ?? this.latestActionableFinding;
            const fallbackTargetPath = this.getActiveFixTargetPath();
            const canUseGroundedFallback = fallbackFinding && (
                canAnchorToCurrentFinding
                || looksLikeFixRequest(trimmed)
                || looksLikeImplementRequest(trimmed)
                || looksLikeFindingFollowUp(trimmed)
            );
            if (canUseGroundedFallback) {
                const fallback = buildFindingFallback(
                    trimmed,
                    fallbackFinding,
                    isRateLimitError(error)
                        ? 'The provider hit a rate limit, so I am falling back to grounded local context for the active finding.'
                        : `${buildProviderFailureMessage(error)} I am falling back to grounded local context for the active finding.`,
                    fallbackTargetPath,
                    Boolean(this.pendingFixPreview),
                );
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    content: fallback.content,
                    kind: 'advisory',
                    actions: fallback.actions,
                };
            } else {
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    content: `${buildProviderFailureMessage(error)} Try again, or ask about the current file, latest scan, or active finding.`,
                    kind: 'advisory',
                };
            }
        }

        void this.persistState();
        this.refresh();
    }

    private buildRecentConversationContext(): string {
        const completedMessages = this.messages
            .slice(0, -2)
            .filter(message => message.role === 'user' || message.role === 'assistant')
            .filter(message => message.content && message.content !== 'Thinking...')
            .slice(-MAX_RECENT_CHAT_CONTEXT_MESSAGES);

        if (!completedMessages.length) {
            return 'Recent conversation context: none';
        }

        let remaining = MAX_RECENT_CHAT_CONTEXT_CHARS;
        const lines: string[] = [];
        for (const message of completedMessages) {
            const role = message.role === 'user' ? 'User' : 'Assistant';
            const perMessageLimit = message.role === 'user' ? 1200 : 800;
            let content = message.content.trim();
            if (content.length > perMessageLimit) {
                content = `${content.slice(0, perMessageLimit)}\n[truncated]`;
            }
            const line = `${role}: ${content}`;
            if (line.length > remaining) {
                lines.push(`${line.slice(0, Math.max(0, remaining))}\n[conversation context truncated]`);
                break;
            }
            lines.push(line);
            remaining -= line.length;
            if (remaining <= 0) {
                break;
            }
        }

        return `Recent conversation context:\n${lines.join('\n\n')}`;
    }

    private async tryHandleLocalAction(prompt: string): Promise<LocalActionResult> {
        if (looksLikeToolHelpRequest(prompt)) {
            const help = buildToolHelpResponse(prompt);
            return {
                handled: true,
                response: help.content,
                kind: 'advisory',
                actions: help.actions,
            };
        }

        const intent = parseChatIntent(prompt);
        if (!intent) {
            return { handled: false };
        }

        if (intent.action === 'scanFile') {
            return this.handleScanFileIntent(intent);
        }

        if (intent.action === 'scanFolder') {
            const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanWorkspace);
            if (result?.status === 'cancelled') {
                return { handled: true, response: 'Folder scan was cancelled.', kind: 'scan' };
            }
            if (result?.status === 'empty') {
                return { handled: true, response: 'No supported source files were found in the selected folder.', kind: 'scan' };
            }
            if (result?.status === 'failed') {
                return {
                    handled: true,
                    response: `Folder scan failed for all files.\nFiles scanned: 0\nTotal findings: 0\nScan errors: ${result.errors.length}`,
                    kind: 'scan',
                };
            }
            if (!result?.completed) {
                return { handled: true, response: 'Folder scan did not complete.', kind: 'scan' };
            }
            const topActionable = getTopActionableFindingResult(result.results ?? []);
            this.lastSelectedScopePaths = (result.results ?? [])
                .map((item: any) => item?.uri?.fsPath)
                .filter((value: unknown): value is string => typeof value === 'string' && value.length > 0);
            this.latestActionableItems = getActionableFindingResults(result.results ?? []);
            this.latestActionableFinding = topActionable?.finding;
            this.latestActionableTargetPath = topActionable?.targetPath;
            const actions: ChatMessageAction[] = buildPrimaryFixAction(this.latestActionableItems);
            actions.push(buildExplainScoreAction('explain-score-scan-folder-intent', result.results ?? []));
            return {
                handled: true,
                response: buildMultiFileScanResponse('Folder scan', result.completed, result.results ?? [], result.errors ?? [], topActionable),
                kind: 'scan',
                actions,
            };
        }

        if (intent.action === 'scanSelectedFiles') {
            const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanSelectedFiles);
            if (result?.status === 'cancelled') {
                return { handled: true, response: 'Selected-files scan was cancelled.', kind: 'scan' };
            }
            if (result?.status === 'empty') {
                return { handled: true, response: 'No supported source files were selected.', kind: 'scan' };
            }
            if (result?.status === 'failed') {
                return {
                    handled: true,
                    response: `Selected-files scan failed for all files.\nFiles scanned: 0\nTotal findings: 0\nScan errors: ${result.errors.length}`,
                    kind: 'scan',
                };
            }
            if (!result?.completed) {
                return { handled: true, response: 'Selected-files scan did not complete.', kind: 'scan' };
            }
            const topActionable = getTopActionableFindingResult(result.results ?? []);
            this.lastSelectedScopePaths = (result.results ?? [])
                .map((item: any) => item?.uri?.fsPath)
                .filter((value: unknown): value is string => typeof value === 'string' && value.length > 0);
            this.latestActionableItems = getActionableFindingResults(result.results ?? []);
            this.latestActionableFinding = topActionable?.finding;
            this.latestActionableTargetPath = topActionable?.targetPath;
            const actions: ChatMessageAction[] = buildPrimaryFixAction(this.latestActionableItems);
            actions.push(buildExplainScoreAction('explain-score-scan-selected-intent', result.results ?? []));
            return {
                handled: true,
                response: buildMultiFileScanResponse('Selected files scan', result.completed, result.results ?? [], result.errors ?? [], topActionable),
                kind: 'scan',
                actions,
            };
        }

        if (intent.action === 'scanOpenEditors') {
            const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanOpenEditors);
            if (result?.status === 'cancelled') {
                return { handled: true, response: 'Open-editors scan was cancelled.', kind: 'scan' };
            }
            if (result?.status === 'empty') {
                return { handled: true, response: 'No supported open editors were available to scan.', kind: 'scan' };
            }
            if (result?.status === 'failed') {
                return {
                    handled: true,
                    response: `Open-editors scan failed for all files.\nFiles scanned: 0\nTotal findings: 0\nScan errors: ${result.errors.length}`,
                    kind: 'scan',
                };
            }
            if (!result?.completed) {
                return { handled: true, response: 'Open-editors scan did not complete.', kind: 'scan' };
            }
            const topActionable = getTopActionableFindingResult(result.results ?? []);
            this.latestActionableItems = getActionableFindingResults(result.results ?? []);
            this.latestActionableFinding = topActionable?.finding;
            this.latestActionableTargetPath = topActionable?.targetPath;
            const actions: ChatMessageAction[] = buildPrimaryFixAction(this.latestActionableItems);
            actions.push(buildExplainScoreAction('explain-score-scan-open-editors-intent', result.results ?? []));
            return {
                handled: true,
                response: buildMultiFileScanResponse('Open editors scan', result.completed, result.results ?? [], result.errors ?? [], topActionable),
                kind: 'scan',
                actions,
            };
        }

        if (intent.action === 'reviewRiskCalibration') {
            const result = await vscode.commands.executeCommand<any>(PROFILE.commands.reviewRiskCalibration);
            return {
                handled: true,
                response: result?.status === 'completed'
                    ? `Opened risk calibration review for ${result.count} stored scan(s).`
                    : 'Risk calibration review is not available yet. Run at least one scan first.',
                kind: 'advisory',
            };
        }

        const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanWorkspaceReport);
            if (result?.status === 'cancelled') {
                return {
                    handled: true,
                    response: 'Report creation was cancelled.',
                    kind: 'scan',
            };
        }
        if (result?.status === 'empty') {
            return {
                handled: true,
                response: 'Report creation could not continue because no supported files were found.',
                kind: 'scan',
            };
        }
        if (result?.status === 'failed') {
            return {
                handled: true,
                response: `Report creation failed because every scanned file errored.\nFiles scanned: 0\nTotal findings: 0\nScan errors: ${result.summary?.errors.length ?? 0}`,
                kind: 'scan',
            };
        }

        const relativeReportPath = vscode.workspace.asRelativePath(result.reportUri, false);
        const topActionable = getTopActionableFindingResult(result.summary.results ?? []);
        this.latestActionableItems = getActionableFindingResults(result.summary.results ?? []);
        this.latestActionableFinding = topActionable?.finding;
        this.latestActionableTargetPath = topActionable?.targetPath;
        return {
            handled: true,
            response: buildMultiFileScanResponse(
                'Vulnerability scan',
                result.summary.completed,
                result.summary.results ?? [],
                result.summary.errors ?? [],
                topActionable,
                relativeReportPath,
            ),
            kind: 'scan',
            actions: [
                ...buildPrimaryFixAction(this.latestActionableItems),
                {
                    ...buildExplainScoreAction('explain-score-report-intent', result.summary.results ?? []),
                },
            ],
        };
    }

    private refresh(): void {
        this.pushState();
    }

    private pushState(): void {
        const provider = this.registry.getActive();
        this.postState(this.buildState(
            this.getFallbackModels(),
            [{ id: provider.id, name: provider.name }],
            `LLM status: checking ${provider.name}...`,
            getProviderSetupHint(provider.id),
            `Backend: ${vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('apiUrl', PROFILE.defaultApiUrl) || PROFILE.defaultApiUrl}`,
            'Licence: checking...',
            false,
            false,
        ));
        void this.pushResolvedState();
    }

    private async handleSetProvider(providerId: string): Promise<void> {
        if (!providerId || !this.registry.getProvider(providerId)) return;
        await this.registry.setActiveProvider(providerId);

        const provider = this.registry.getActive();
        const models = await this.getModelsForProvider(provider);
        if (models.length && !models.includes(provider.selectedModel)) {
            await this.registry.setProviderModel(provider.id, models[0]);
        }

        this.messages.push({
            role: 'system',
            content: `Provider switched to ${provider.name}.`,
            kind: 'advisory',
        });
        void this.persistState();
        this.refresh();
    }

    private async handleMessageAction(messageIndex: number, actionId: string): Promise<void> {
        const message = this.messages[messageIndex];
        const action = message?.actions?.find(item => item.id === actionId);
        if (!action) {
            return;
        }

        if (action.kind === 'openSource' && action.path) {
            this.currentMode = 'repo';
            const document = await vscode.workspace.openTextDocument(vscode.Uri.file(action.path));
            const editor = await vscode.window.showTextDocument(document, { preview: false });
            if (typeof action.line === 'number' && action.line > 0) {
                const position = new vscode.Position(action.line - 1, 0);
                editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
            }
            return;
        }

        if (action.kind === 'applyFixPreview') {
            this.currentMode = 'fix';
            await this.applyPendingFixPreview();
            return;
        }

        if (action.kind === 'discardFixPreview') {
            this.currentMode = 'fix';
            const discardedPreview = this.pendingFixPreview;
            this.pendingFixPreview = undefined;
            this.messages.push({
                role: 'assistant',
                content: discardedPreview
                    ? `Discarded the fix preview for ${vscode.workspace.asRelativePath(vscode.Uri.file(discardedPreview.targetPath), false)}. The original file was left unchanged and no code was written.`
                    : 'Discarded the current fix preview. The original file was left unchanged and no code was written.',
                kind: 'advisory',
            });
            this.emitUsageTelemetry('fix_preview_discarded', {
                file_count: discardedPreview?.changes?.length ?? 1,
                canonical_id: discardedPreview?.finding.canonicalId ?? null,
                severity: discardedPreview?.finding.severity ?? null,
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action.kind === 'generateFixPreview' && action.finding) {
            this.currentMode = 'fix';
            await this.generateFixPreview(action.finding, action.path);
            return;
        }

        if (action.kind === 'generateBatchFixPreview' && action.findings?.length) {
            this.currentMode = 'fix';
            await this.generateBatchFixPreview(action.findings);
            return;
        }

        if (action.kind === 'explainScore') {
            this.currentMode = 'scan';
            this.latestActionableFinding = findTopFindingInCalibrationRecords(action.calibrationRecords) ?? this.latestActionableFinding;
            await vscode.commands.executeCommand(PROFILE.commands.reviewRiskCalibration, action.calibrationRecords);
            this.messages.push({
                role: 'assistant',
                content: 'Opened the score review so you can inspect how overall score and top-risk findings relate.',
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action.kind === 'restorePreviousChat') {
            if (this.restorableMessages?.length) {
                this.messages.splice(0, this.messages.length, ...this.restorableMessages);
                void this.persistState();
                this.refresh();
            }
            return;
        }

        if (action.kind === 'dismissMessage' && messageIndex >= 0) {
            this.messages.splice(messageIndex, 1);
            void this.persistState();
            this.refresh();
        }

        if (action.kind === 'quickAction' && action.quickAction) {
            await this.handleQuickAction(action.quickAction);
        }
    }

    private buildActiveSnippetForFinding(finding: Finding): string | undefined {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return undefined;
        }

        const lines = editor.document.getText().split(/\r?\n/);
        const start = Math.max(0, finding.line - 2);
        const end = Math.min(lines.length, Math.max(finding.lineEnd ?? finding.line, finding.line) + 1);
        return lines
            .slice(start, end)
            .map((text, index) => `${String(start + index + 1).padStart(4, ' ')} | ${text}`)
            .join('\n');
    }

    private createFullDocumentRange(text: string): vscode.Range {
        const lines = text.split(/\r?\n/);
        const endLine = Math.max(0, lines.length - 1);
        const endCharacter = lines[endLine]?.length ?? 0;
        return new vscode.Range(new vscode.Position(0, 0), new vscode.Position(endLine, endCharacter));
    }

    private async resolveWorkspaceRelativePath(relativePath: string): Promise<string | undefined> {
        if (path.isAbsolute(relativePath)) {
            const absoluteUri = vscode.Uri.file(relativePath);
            if ((await tryReadWorkspaceFile(absoluteUri)) !== undefined) {
                return absoluteUri.fsPath;
            }
        }

        for (const folder of vscode.workspace.workspaceFolders ?? []) {
            const candidate = vscode.Uri.joinPath(folder.uri, relativePath);
            if ((await tryReadWorkspaceFile(candidate)) !== undefined) {
                return candidate.fsPath;
            }
        }

        return undefined;
    }

    private async buildFindingContextBundle(finding: Finding): Promise<FindingContextBundle> {
        const workingScope = this.getWorkingScope();
        const editor = vscode.window.activeTextEditor;
        const snippet = this.buildActiveSnippetForFinding(finding);
        const nearbyContext = (workingScope === 'scanOpenEditors' || workingScope === 'scanFolder') && editor
            ? await buildNearbyProjectContext(editor.document, finding)
            : undefined;
        const latestReportContext = buildLatestReportPromptContext(this.storage);
        const groundedFrameworks = getGroundedFrameworkLabels(this.getFrameworks());
        const groundedCheatSheets = finding.canonicalId
            ? getGroundedCheatSheetLabelsForIssueIds([finding.canonicalId]).slice(0, 2)
            : [];
        const workingScopeContext = await this.buildWorkingScopeContext(workingScope);
        const sourceActions: ChatMessageAction[] = [];

        if (editor) {
            sourceActions.push({
                id: `open-active-${finding.id ?? finding.line}`,
                label: 'Open active file',
                kind: 'openSource',
                path: editor.document.uri.fsPath,
                line: finding.line,
            });
        }

        for (const [index, relativePath] of extractNearbyContextSources(nearbyContext).entries()) {
            const absolutePath = await this.resolveWorkspaceRelativePath(relativePath);
            if (!absolutePath) {
                continue;
            }

            sourceActions.push({
                id: `open-nearby-${index}`,
                label: `Open ${relativePath}`,
                kind: 'openSource',
                path: absolutePath,
            });
        }

        return {
            promptContext: [
                buildFindingPromptContext(finding, snippet),
                workingScopeContext.promptContext,
                nearbyContext ?? 'Nearby project context: none',
                latestReportContext?.promptContext ?? 'Latest report context: none',
            ].join('\n\n'),
            sourceSummary: buildFindingContextSummary({
                finding,
                hasActiveSnippet: Boolean(snippet),
                nearbyContext,
                hasLatestReportContext: Boolean(latestReportContext),
                groundedFrameworks,
                groundedCheatSheets,
            }) + `\n- Working scope: ${getWorkingScopeLabel(workingScope)}`,
            sourceActions,
        };
    }

    private async handleSetModel(model: string): Promise<void> {
        const provider = this.registry.getActive();
        if (!model) return;
        await this.registry.setProviderModel(provider.id, model);
        this.messages.push({
            role: 'system',
            content: `Model switched to ${model}.`,
            kind: 'advisory',
        });
        this.currentMode = 'general';
        void this.persistState();
        this.refresh();
    }

    private async handleQuickAction(action: string): Promise<void> {
        if (!action) return;

        const isScanAction = action === 'scanFile'
            || action === 'scanSelectedFiles'
            || action === 'scanOpenEditors'
            || action === 'scanFolder'
            || action === 'scanReport'
            || action === 'scanSummaryReport'
            || action === 'scanFullReport';

        if (isScanAction || action === 'reviewRiskCalibration') {
            this.currentMode = 'scan';
        } else {
            this.currentMode = 'general';
        }

        if (action === 'selectFrameworks') {
            await vscode.commands.executeCommand(PROFILE.commands.selectFrameworks);
            this.refresh();
            return;
        }

        if (action === 'setupAI') {
            await vscode.commands.executeCommand(PROFILE.commands.setupAI);
            const provider = this.registry.getActive();
            const configured = await provider.isConfigured().catch(() => false);
            this.messages.push({
                role: 'system',
                content: configured
                    ? `${provider.name} is configured and ready using ${provider.selectedModel}.`
                    : `${provider.name} is selected but not configured yet. Finish configuring it or switch to another provider.`,
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'configureBackend') {
            await vscode.commands.executeCommand(PROFILE.commands.configureBackend);
            const apiUrl = vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('apiUrl', PROFILE.defaultApiUrl) || PROFILE.defaultApiUrl;
            this.messages.push({
                role: 'system',
                content: apiUrl === PROFILE.defaultApiUrl
                    ? `Owlvex is using this build's packaged backend: ${apiUrl}.`
                    : `Owlvex is using an explicit backend override: ${apiUrl}.`,
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'enterLicence') {
            await vscode.commands.executeCommand(PROFILE.commands.enterLicence);
            const licenceInfo = this.licenceMgr.getCachedInfo();
            this.messages.push({
                role: 'system',
                content: licenceInfo
                    ? `Licence is ready: ${buildLicenceStatusSummary(licenceInfo)}.`
                    : 'Licence setup finished. If validation failed, confirm the packaged backend is reachable and only use a backend override when you intentionally need a different Owlvex environment.',
                kind: 'advisory',
                actions: licenceInfo
                    ? [
                        {
                            id: 'quick-test-trial-setup',
                            label: 'Test Setup',
                            kind: 'quickAction',
                            quickAction: 'testTrialSetup',
                        },
                        {
                            id: 'quick-view-plans',
                            label: 'View Plans',
                            kind: 'quickAction',
                            quickAction: 'viewPlans',
                        },
                    ]
                    : [
                        {
                            id: 'quick-test-ai',
                            label: 'Configure LLM',
                            kind: 'quickAction',
                            quickAction: 'setupAI',
                        },
                    ],
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'toggleTelemetry') {
            await vscode.commands.executeCommand(PROFILE.commands.toggleTelemetry);
            const licenceInfo = this.licenceMgr.getCachedInfo();
            this.messages.push({
                role: 'system',
                content: licenceInfo?.features.telemetryOptOut
                    ? [
                        'Telemetry preference:',
                        `- Optional product telemetry is currently ${licenceInfo.features.telemetryEnabled ? 'enabled' : 'disabled'}.`,
                        '- Licensing, quota enforcement, and abuse controls still require minimum operational checks.',
                    ].join('\n')
                    : [
                        'Telemetry preference:',
                        `- ${licenceInfo?.plan === 'trial' ? 'Trial' : 'Free'} access requires product telemetry.`,
                        '- Paid licences can opt out of optional product usage telemetry.',
                    ].join('\n'),
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'startTrial') {
            await vscode.commands.executeCommand(PROFILE.commands.registerAccess, 'trial');
            const licenceInfo = this.licenceMgr.getCachedInfo();
            this.messages.push({
                role: 'system',
                content: licenceInfo?.plan === 'trial'
                    ? [
                        `Trial is active for ${licenceInfo.teamName}.`,
                        `Status: ${buildLicenceStatusSummary(licenceInfo)}`,
                        'Recommended next steps:',
                        ...buildPlanNextStepGuidance(licenceInfo).map(line => `- ${line}`),
                        '- Use Test Trial Setup if you want to re-check backend, licence, and LLM connectivity',
                    ].join('\n')
                    : [
                        'Trial onboarding:',
                        '- Register a tracked trial with your email',
                        '- Verify the email code to activate the licence',
                        '- The packaged backend should already be selected for this build',
                        '- Configure your LLM connection',
                        '- Run a real scan to experience the full workflow',
                    ].join('\n'),
                kind: 'advisory',
                actions: licenceInfo?.plan === 'trial'
                    ? [
                        {
                            id: 'trial-test-setup',
                            label: 'Test Trial Setup',
                            kind: 'quickAction',
                            quickAction: 'testTrialSetup',
                        },
                        {
                            id: 'trial-configure-llm',
                            label: 'Configure LLM',
                            kind: 'quickAction',
                            quickAction: 'setupAI',
                        },
                    ]
                    : [
                        {
                            id: 'trial-register',
                            label: 'Register Trial',
                            kind: 'quickAction',
                            quickAction: 'startTrial',
                        },
                        {
                            id: 'trial-configure-llm',
                            label: 'Configure LLM',
                            kind: 'quickAction',
                            quickAction: 'setupAI',
                        },
                    ],
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'useFree') {
            await vscode.commands.executeCommand(PROFILE.commands.registerAccess, 'free');
            const licenceInfo = this.licenceMgr.getCachedInfo();
            this.messages.push({
                role: 'system',
                content: licenceInfo?.plan === 'free'
                    ? [
                        `Free access is active for ${licenceInfo.teamName}.`,
                        `Status: ${buildLicenceStatusSummary(licenceInfo)}`,
                        'Recommended next steps:',
                        ...buildPlanNextStepGuidance(licenceInfo).map(line => `- ${line}`),
                    ].join('\n')
                    : [
                        'Free onboarding:',
                        '- Register Free access with your email',
                        '- Verify the email code to activate the licence',
                        '- The packaged backend should already be selected for this build',
                        '- Run a deterministic scan to validate value quickly',
                    ].join('\n'),
                kind: 'advisory',
                actions: licenceInfo?.plan === 'free'
                    ? [
                        {
                            id: 'free-test-setup',
                            label: 'Test Trial Setup',
                            kind: 'quickAction',
                            quickAction: 'testTrialSetup',
                        },
                        {
                            id: 'free-start-trial',
                            label: 'Start Trial',
                            kind: 'quickAction',
                            quickAction: 'startTrial',
                        },
                    ]
                    : [
                        {
                            id: 'free-register',
                            label: 'Use Free',
                            kind: 'quickAction',
                            quickAction: 'useFree',
                        },
                    ],
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'viewPlans') {
            this.messages.push({
                role: 'system',
                content: [
                    'Owlvex plans:',
                    '- Free: register and verify your email, then use the full workflow with up to 50 scans per month',
                    '- Trial: register and verify your email for 7-day full product access with higher-volume evaluation',
                    '- Developer: full individual workflow with ongoing AI-assisted use',
                    '',
                    'Upgrade path:',
                    '- Start with Free to validate value with the complete product surface',
                    '- Use Trial to evaluate at higher volume before committing',
                    '- Move to Developer for ongoing use without free-tier limits',
                ].join('\n'),
                kind: 'advisory',
                actions: [
                    {
                        id: 'plans-use-free',
                        label: 'Use Free',
                        kind: 'quickAction',
                        quickAction: 'useFree',
                    },
                    {
                        id: 'plans-start-trial',
                        label: 'Start Trial',
                        kind: 'quickAction',
                        quickAction: 'startTrial',
                    },
                    {
                        id: 'plans-enter-licence',
                        label: 'Enter Licence',
                        kind: 'quickAction',
                        quickAction: 'enterLicence',
                    },
                ],
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'showOnboarding') {
            const result = await vscode.commands.executeCommand<any>(PROFILE.commands.testTrialSetup);
            const summary = Array.isArray(result?.summary) ? result.summary : [];
            const projectRoot = getProjectRootSummaryFromConfig();
            const lines = [
                'Owlvex onboarding checklist:',
                `- Backend connection: ${result?.backend ? 'ready' : 'package default unreachable'}`,
                `- Licence or registration: ${result?.licence ? 'ready' : 'needs setup'}`,
                `- Project root: ${projectRoot !== 'not set' ? projectRoot : 'needs selection'}`,
                `- LLM connection: ${result?.provider ? 'ready' : 'needs setup'}`,
                `- First meaningful scan: ${result?.backend && result?.licence ? 'available now' : 'blocked until setup is complete'}`,
                '',
                'Current status:',
                ...(summary.length ? summary.map((line: string) => `- ${line}`) : ['- Run Test Trial Setup to refresh the live status.']),
            ];

            const actions: ChatMessageAction[] = [];
            if (!result?.licence) {
                actions.push({
                    id: 'onboarding-use-free',
                    label: 'Use Free',
                    kind: 'quickAction',
                    quickAction: 'useFree',
                });
                actions.push({
                    id: 'onboarding-start-trial',
                    label: 'Start Trial',
                    kind: 'quickAction',
                    quickAction: 'startTrial',
                });
            }
            if (!result?.provider) {
                actions.push({
                    id: 'onboarding-configure-llm',
                    label: 'Configure LLM',
                    kind: 'quickAction',
                    quickAction: 'setupAI',
                });
            }
            if (projectRoot === 'not set') {
                actions.push({
                    id: 'onboarding-select-project-root',
                    label: 'Select Project Root',
                    kind: 'quickAction',
                    quickAction: 'selectProjectRoot',
                });
            }
            if (result?.backend && result?.licence) {
                actions.push({
                    id: 'onboarding-scan-workspace',
                    label: 'Scan Workspace',
                    kind: 'quickAction',
                    quickAction: 'scanFolder',
                });
            }

            this.messages.push({
                role: 'system',
                content: lines.join('\n'),
                kind: 'advisory',
                actions,
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'testTrialSetup') {
            const result = await vscode.commands.executeCommand<any>(PROFILE.commands.testTrialSetup);
            this.messages.push({
                role: 'system',
                content: result?.summary?.length
                    ? result.summary.join('\n')
                    : 'Trial setup check finished. Review the backend, licence, and LLM status above.',
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'securityBoundary') {
            const projectRoot = getProjectRootSummaryFromConfig();
            this.messages.push({
                role: 'system',
                content: [
                    'Owlvex security boundary:',
                    '- Deterministic scanning runs locally in the extension.',
                    '- Source code for AI-backed review goes directly to your selected provider.',
                    '- Owlvex backend is intended to receive licence, prompt, pack, and scan/comparison metadata rather than raw source code.',
                    `- Repo-wide AI context stays inside the selected project root (${projectRoot !== 'not set' ? projectRoot : 'not set yet'}).`,
                    '- Project context stays local by default and is only used in direct AI review when configured.',
                    '- Fixes stay in preview until you choose Keep fix.',
                ].join('\n'),
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'openProjectContext') {
            await vscode.commands.executeCommand(PROFILE.commands.openProjectContext);
            const projectContextSummary = getProjectContextSummaryFromConfig();
            this.messages.push({
                role: 'system',
                content: projectContextSummary !== 'none'
                    ? `Project context is ready: ${projectContextSummary}.`
                    : 'Opened project context. Save or configure it locally to reuse it in scans.',
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'selectProjectRoot') {
            await vscode.commands.executeCommand(PROFILE.commands.selectProjectRoot);
            const projectRoot = getProjectRootSummaryFromConfig();
            this.messages.push({
                role: 'system',
                content: projectRoot !== 'not set'
                    ? `Project root is now ${projectRoot}. Repo-wide AI context and workspace scans will stay inside this boundary.`
                    : 'Project root selection was not changed.',
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'testAI') {
            await vscode.commands.executeCommand(PROFILE.commands.testAI);
            const provider = this.registry.getActive();
            const configured = await provider.isConfigured().catch(() => false);
            this.messages.push({
                role: 'system',
                content: configured
                    ? `Connection test ran for ${provider.name}.`
                    : `${provider.name} is selected but not configured yet. Finish configuring it or switch to another provider.`,
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        if (action === 'reviewRiskCalibration') {
            const result = await vscode.commands.executeCommand<any>(PROFILE.commands.reviewRiskCalibration);
            this.messages.push({
                role: 'system',
                content: result?.status === 'completed'
                    ? `Opened risk calibration review for ${result.count} stored scan(s).`
                    : 'Risk calibration review is not available yet. Run at least one scan first.',
                kind: 'advisory',
            });
            void this.persistState();
            this.refresh();
            return;
        }

        this.messages.push({
            role: 'system',
            content: `Running ${action}...`,
            kind: isScanAction
                ? 'scan'
                : 'advisory',
        });
        this.refresh();

        try {
            if (action === 'scanFile') {
                const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanFile);
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.latestActionableFinding = result?.result?.findings
                    ?.slice()
                    ?.sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))[0];
                this.latestActionableTargetPath = result?.uri?.fsPath;
                this.latestActionableItems = this.latestActionableFinding && result?.uri
                    ? [{ finding: this.latestActionableFinding, targetPath: result.uri.fsPath }]
                    : [];
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed' && result.result
                        ? [
                            `Scan completed for the selected file.`,
                            ...buildScanSummaryLines(result.result),
                            ...this.buildProviderComparisonNotes([{ uri: result.uri, result: result.result }]),
                        ].join('\n')
                        : 'File scan did not complete.',
                    actions: result?.status === 'completed' && result?.result && result?.uri
                        ? [
                            ...buildPrimaryFixAction(this.latestActionableItems),
                            buildExplainScoreAction('explain-score-file', [{ uri: result.uri, result: result.result }]),
                        ]
                        : undefined,
                };
            } else if (action === 'scanSelectedFiles') {
                const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanSelectedFiles);
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.latestActionableFinding = result?.results
                    ?.flatMap((item: any) => item.result.findings)
                    ?.slice()
                    ?.sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))[0];
                this.lastSelectedScopePaths = (result?.results ?? [])
                    .map((item: any) => item?.uri?.fsPath)
                    .filter((value: unknown): value is string => typeof value === 'string' && value.length > 0);
                this.latestActionableTargetPath = getTopActionableFindingResult(result?.results ?? [])?.targetPath;
                this.latestActionableItems = getActionableFindingResults(result?.results ?? []);
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed'
                        ? [
                            `Selected-files scan completed.`,
                            `Files scanned: ${result.completed}`,
                            `Total findings: ${result.totalFindings}`,
                            summarizeEngineEvidence(result.results.flatMap((item: any) => item.result.findings)),
                            summarizeIssueFamilies(result.results.flatMap((item: any) => item.result.findings)),
                            ...buildGroundedRemediationHighlights(result.results.flatMap((item: any) => item.result.findings))
                                .map((line, index) => `Remediation ${index + 1}: ${line}`),
                            ...this.buildProviderComparisonNotes(result.results ?? []),
                            result.errors.length
                                ? `Scan errors: ${result.errors.length}`
                                : 'No scan errors were reported.',
                        ].join('\n')
                        : result?.status === 'failed'
                            ? [
                                `Selected-files scan failed for all files.`,
                                `Files scanned: 0`,
                                `Total findings: 0`,
                                `Issue families: unresolved`,
                                `Scan errors: ${result.errors.length}`,
                            ].join('\n')
                        : result?.status === 'empty'
                            ? 'No supported source files were selected.'
                            : 'Selected-files scan was cancelled.',
                    actions: result?.status === 'completed'
                        ? [
                            ...buildPrimaryFixAction(this.latestActionableItems),
                            buildExplainScoreAction('explain-score-selected', result.results ?? []),
                        ]
                        : undefined,
                };
            } else if (action === 'scanOpenEditors') {
                const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanOpenEditors);
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.latestActionableFinding = result?.results
                    ?.flatMap((item: any) => item.result.findings)
                    ?.slice()
                    ?.sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))[0];
                this.latestActionableTargetPath = getTopActionableFindingResult(result?.results ?? [])?.targetPath;
                this.latestActionableItems = getActionableFindingResults(result?.results ?? []);
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed'
                        ? [
                            `Open-editors scan completed.`,
                            `Files scanned: ${result.completed}`,
                            `Total findings: ${result.totalFindings}`,
                            summarizeEngineEvidence(result.results.flatMap((item: any) => item.result.findings)),
                            summarizeIssueFamilies(result.results.flatMap((item: any) => item.result.findings)),
                            ...buildGroundedRemediationHighlights(result.results.flatMap((item: any) => item.result.findings))
                                .map((line, index) => `Remediation ${index + 1}: ${line}`),
                            ...this.buildProviderComparisonNotes(result.results ?? []),
                            result.errors.length
                                ? `Scan errors: ${result.errors.length}`
                                : 'No scan errors were reported.',
                        ].join('\n')
                        : result?.status === 'failed'
                            ? [
                                `Open-editors scan failed for all files.`,
                                `Files scanned: 0`,
                                `Total findings: 0`,
                                `Issue families: unresolved`,
                                `Scan errors: ${result.errors.length}`,
                            ].join('\n')
                        : result?.status === 'empty'
                            ? 'No supported open editors were available to scan.'
                            : 'Open-editors scan was cancelled.',
                    actions: result?.status === 'completed'
                        ? [
                            ...buildPrimaryFixAction(this.latestActionableItems),
                            buildExplainScoreAction('explain-score-open-editors', result.results ?? []),
                        ]
                        : undefined,
                };
            } else if (action === 'scanFolder') {
                const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanWorkspace);
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.latestActionableFinding = result?.results
                    ?.flatMap((item: any) => item.result.findings)
                    ?.slice()
                    ?.sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))[0];
                this.latestActionableTargetPath = getTopActionableFindingResult(result?.results ?? [])?.targetPath;
                this.latestActionableItems = getActionableFindingResults(result?.results ?? []);
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed'
                        ? [
                            `Folder scan completed.`,
                            `Files scanned: ${result.completed}`,
                            `Total findings: ${result.totalFindings}`,
                            summarizeEngineEvidence(result.results.flatMap((item: any) => item.result.findings)),
                            summarizeIssueFamilies(result.results.flatMap((item: any) => item.result.findings)),
                            ...buildGroundedRemediationHighlights(result.results.flatMap((item: any) => item.result.findings))
                                .map((line, index) => `Remediation ${index + 1}: ${line}`),
                            ...this.buildProviderComparisonNotes(result.results ?? []),
                            result.results.some((item: any) => (item.result.warnings ?? []).length)
                                ? `Scan warnings: ${result.results.reduce((total: number, item: any) => total + (item.result.warnings ?? []).length, 0)}`
                                : 'No scan warnings were reported.',
                            result.errors.length
                                ? `Scan errors: ${result.errors.length}`
                                : 'No scan errors were reported.',
                        ].join('\n')
                        : result?.status === 'failed'
                            ? [
                                `Folder scan failed for all files.`,
                                `Files scanned: 0`,
                                `Total findings: 0`,
                                `Issue families: unresolved`,
                                `Scan errors: ${result.errors.length}`,
                            ].join('\n')
                        : result?.status === 'empty'
                            ? 'No supported source files were found in the selected folder.'
                            : 'Folder scan was cancelled.',
                    actions: result?.status === 'completed'
                        ? [
                            ...buildPrimaryFixAction(this.latestActionableItems),
                            buildExplainScoreAction('explain-score-folder', result.results ?? []),
                        ]
                        : undefined,
                };
            } else if (action === 'scanReport' || action === 'scanSummaryReport' || action === 'scanFullReport') {
                const result = await vscode.commands.executeCommand<any>(
                    PROFILE.commands.scanWorkspaceReport,
                    action === 'scanSummaryReport'
                        ? { reportVariant: 'summary' }
                        : action === 'scanFullReport'
                            ? { reportVariant: 'full' }
                            : undefined,
                );
                if (result?.status === 'cancelled') {
                    this.messages.pop();
                    void this.persistState();
                    this.refresh();
                    return;
                }
                this.latestActionableFinding = result?.summary?.results
                    ?.flatMap((item: any) => item.result.findings)
                    ?.slice()
                    ?.sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))[0];
                this.latestActionableTargetPath = getTopActionableFindingResult(result?.summary?.results ?? [])?.targetPath;
                this.latestActionableItems = getActionableFindingResults(result?.summary?.results ?? []);
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'scan',
                    content: result?.status === 'completed' && result.summary
                        ? [
                            `Vulnerability scan completed for ${result.summary.completed} file(s).`,
                            `Total findings: ${result.summary.totalFindings}`,
                            `Average file risk score: ${result.averageScore.toFixed(1)}/10`,
                            summarizeEngineEvidence(result.summary.results.flatMap((item: any) => item.result.findings)),
                            summarizeIssueFamilies(result.summary.results.flatMap((item: any) => item.result.findings)),
                            ...buildGroundedRemediationHighlights(result.summary.results.flatMap((item: any) => item.result.findings))
                                .map((line, index) => `Remediation ${index + 1}: ${line}`),
                            ...this.buildProviderComparisonNotes(result.summary.results ?? []),
                            result.summary.results.some((item: any) => (item.result.warnings ?? []).length)
                                ? `Scan warnings: ${result.summary.results.reduce((total: number, item: any) => total + (item.result.warnings ?? []).length, 0)}`
                                : 'No scan warnings were reported.',
                            `${result.reportVariant === 'summary' ? 'Summary report' : 'Full evidence report'}: ${vscode.workspace.asRelativePath(result.reportUri, false)}`,
                        ].join('\n')
                        : result?.status === 'failed'
                            ? [
                                `Report creation failed because every scanned file errored.`,
                                `Files scanned: 0`,
                                `Total findings: 0`,
                                `Issue families: unresolved`,
                                `Scan errors: ${result.summary?.errors.length ?? 0}`,
                            ].join('\n')
                        : result?.status === 'empty'
                            ? 'Report creation could not continue because no supported files were found.'
                            : 'Report creation was cancelled.',
                    actions: result?.status === 'completed'
                        ? [
                            ...buildPrimaryFixAction(this.latestActionableItems),
                            buildExplainScoreAction('explain-score-report', result.summary?.results ?? []),
                        ]
                        : undefined,
                };
            } else {
                this.messages[this.messages.length - 1] = {
                    role: 'assistant',
                    kind: 'advisory',
                    content: `Unknown action: ${action}`,
                };
            }
        } catch (error: any) {
            this.messages[this.messages.length - 1] = {
                role: 'assistant',
                kind: isScanAction ? 'scan' : 'advisory',
                content: `Action failed: ${error.message}`,
            };
        }

        void this.persistState();
        this.refresh();
    }

    private buildProviderComparisonNotes(results: Array<{ uri: vscode.Uri; result: ScanResult }>): string[] {
        const notes: string[] = [];
        for (const item of results) {
            const key = normalizeReviewedPath(item.uri.fsPath);
            const previous = this.recentScanSnapshotsByPath.get(key);
            const current: RecentScanSnapshot = {
                provider: item.result.provider || 'unknown provider',
                model: item.result.model || 'unknown model',
                findingCount: item.result.findings.length,
                score: item.result.score,
            };
            const providerChanged = Boolean(previous)
                && (previous!.provider !== current.provider || previous!.model !== current.model);
            const label = vscode.workspace.asRelativePath(item.uri, false);

            if ((item.result.providerComparisonNotes?.length ?? 0) || (item.result.providerDisagreementProofs?.length ?? 0)) {
                notes.push(...(item.result.providerComparisonNotes ?? []));
                notes.push(...(item.result.providerDisagreementProofs ?? []).map(formatProviderDisagreementProof));
                this.recentScanSnapshotsByPath.set(key, current);
                continue;
            }

            if (previous && providerChanged && previous.findingCount === 0 && current.findingCount > 0) {
                notes.push(`Provider disagreement: ${previous.provider} / ${previous.model} previously reported 0 findings for ${label}; ${current.provider} / ${current.model} now reports ${current.findingCount}. Treat clean scans as provider/model-scoped evidence.`);
            } else if (previous && providerChanged && previous.findingCount > 0 && current.findingCount === 0) {
                notes.push(`Provider-scoped clean result: ${current.provider} / ${current.model} reports 0 findings for ${label}, while ${previous.provider} / ${previous.model} previously reported ${previous.findingCount}. Consider a second-provider review before calling the file clean.`);
            } else if (!previous && current.findingCount === 0) {
                notes.push(`Clean result scope: ${current.provider} / ${current.model} reported 0 findings for ${label}; this is not proof of absence across other models or deeper review.`);
            }

            this.recentScanSnapshotsByPath.set(key, current);
        }

        return notes.slice(0, 3);
    }

    private async persistState(): Promise<void> {
        const persisted = this.messages.slice(-MAX_PERSISTED_MESSAGES);
        await this.storage.update(CHAT_STATE_KEY, persisted);
    }

    private async recordFixBenchmarkResult(update: FixBenchmarkUpdate): Promise<void> {
        const workspaceFolder = typeof vscode.workspace.getWorkspaceFolder === 'function'
            ? vscode.workspace.getWorkspaceFolder(update.targetUri)
            : (vscode.workspace.workspaceFolders ?? []).find(folder =>
                normalizeReviewedPath(update.targetUri.fsPath).startsWith(normalizeReviewedPath(folder.uri.fsPath)),
            );
        const workspaceRoot = workspaceFolder?.uri.fsPath;
        if (!workspaceRoot) {
            return;
        }

        const manifestPath = path.join(workspaceRoot, FIX_BENCHMARK_MANIFEST_RELATIVE_PATH);
        let manifestRaw: string;
        try {
            manifestRaw = await fs.readFile(manifestPath, 'utf8');
        } catch {
            return;
        }

        let manifest: FixBenchmarkManifest;
        try {
            manifest = JSON.parse(manifestRaw) as FixBenchmarkManifest;
        } catch {
            return;
        }

        const relativeTargetPath = normalizeReviewedPath(path.relative(workspaceRoot, update.targetUri.fsPath));
        const expectation = (manifest.expectations ?? []).find(candidate =>
            normalizeReviewedPath(candidate.file) === relativeTargetPath,
        );
        if (!expectation) {
            return;
        }

        const resultsPath = path.join(workspaceRoot, FIX_BENCHMARK_RESULTS_RELATIVE_PATH);
        let results: FixBenchmarkResultsFile = {
            benchmark: manifest.name,
            runs: [],
        };
        try {
            const existingRaw = await fs.readFile(resultsPath, 'utf8');
            results = JSON.parse(existingRaw) as FixBenchmarkResultsFile;
            if (!Array.isArray(results.runs)) {
                results.runs = [];
            }
        } catch {
            results = {
                benchmark: manifest.name,
                description: 'Latest auto-recorded fix benchmark results captured from Owlvex review-and-verify flows.',
                runs: [],
            };
        }

        const changedFiles = update.reviewedPaths.map(filePath =>
            path.relative(workspaceRoot, filePath).replace(/\\/g, '/'),
        );
        const introducedHighRiskFindings = update.rescanned
            ? update.rescanned.findings.some(candidate =>
                severityRank(candidate.severity) >= severityRank('HIGH')
                && !this.isSameFindingFamily(candidate, update.finding),
            )
            : null;

        const nextRun: FixBenchmarkRunRecord = {
            caseId: expectation.caseId,
            attempted: true,
            previewGenerated: true,
            appliedCleanly: update.appliedCleanly,
            filesChanged: changedFiles,
            syntaxValid: inferSyntaxValidity(update.targetUri.fsPath, update.patchedText ?? '', update.rescanned),
            targetFindingRemoved: update.rescanned ? !update.matchingFinding : null,
            introducedHighRiskFindings,
            notes: update.notes,
        };

        const existingIndex = results.runs.findIndex(run => run.caseId === expectation.caseId);
        if (existingIndex >= 0) {
            results.runs[existingIndex] = nextRun;
        } else {
            results.runs.push(nextRun);
        }

        await fs.mkdir(path.dirname(resultsPath), { recursive: true });
        await fs.writeFile(resultsPath, JSON.stringify(results, null, 2), 'utf8');
    }

    private isSameFindingFamily(candidate: Finding, reference: Finding): boolean {
        const normalize = (value?: string): string | undefined => {
            const normalized = value?.trim().toLowerCase();
            return normalized ? normalized : undefined;
        };
        const candidateCanonicalId = normalize(candidate.canonicalId);
        const referenceCanonicalId = normalize(reference.canonicalId);
        if (candidateCanonicalId && referenceCanonicalId && candidateCanonicalId === referenceCanonicalId) {
            return true;
        }

        const candidateTitles = new Set(
            [candidate.title, candidate.canonicalTitle]
                .map(value => normalize(value))
                .filter((value): value is string => Boolean(value)),
        );
        const referenceTitles = [reference.title, reference.canonicalTitle]
            .map(value => normalize(value))
            .filter((value): value is string => Boolean(value));

        return referenceTitles.some(title => candidateTitles.has(title));
    }

    private getRestorableMessages(): ChatMessage[] | undefined {
        const archived = this.storage.get<ChatMessage[]>(CHAT_STATE_KEY, []);
        if (!Array.isArray(archived) || archived.length <= 1) {
            return undefined;
        }

        return archived;
    }

    private resetToFreshChat(): void {
        this.messages.splice(0, this.messages.length, ...buildDefaultChatMessages());
        this.pendingFixPreview = undefined;
        this.latestActionableFinding = undefined;
        this.latestActionableTargetPath = undefined;
        this.latestActionableItems = [];
        this.currentMode = 'general';
    }

    private inferConversationMode(prompt: string, options: UserPromptOptions = {}, canAnchorToCurrentFinding = false): ConversationMode {
        if (parseChatIntent(prompt)) {
            return 'scan';
        }

        if (
            Boolean(this.pendingFixPreview)
            || Boolean(options.suggestedFinding)
            || looksLikeFixRequest(prompt)
            || looksLikeImplementRequest(prompt)
            || (canAnchorToCurrentFinding && looksLikeFindingFollowUp(prompt))
        ) {
            return 'fix';
        }

        return looksLikeRepoQuestion(prompt) ? 'repo' : 'general';
    }

    private getLatestReportFinding(): Finding | undefined {
        const raw = this.storage.get<any>(LAST_REPORT_SNAPSHOT_KEY);
        if (!raw?.results?.length) {
            return undefined;
        }

        const findings = (Array.isArray(raw.results) ? raw.results : [])
            .flatMap((item: any) => item?.result?.findings ?? [])
            .filter((item: any) => item && typeof item.line === 'number');

        return findings
            .slice()
            .sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))[0];
    }

    private getActiveFixTargetPath(): string | undefined {
        return this.pendingFixPreview?.targetPath
            ?? this.latestActionableTargetPath
            ?? vscode.window.activeTextEditor?.document.uri.fsPath;
    }

    private buildFixFollowUpActions(prompt: string, suggestedFinding?: Finding): ChatMessageAction[] | undefined {
        if (this.pendingFixPreview && (looksLikeFixRequest(prompt) || looksLikeImplementRequest(prompt) || looksLikeFindingFollowUp(prompt))) {
            const finding = this.pendingFixPreview.finding ?? suggestedFinding ?? this.latestActionableFinding;
            const targetPath = this.getActiveFixTargetPath();
            return buildActiveFixPreviewActions({
                finding,
                targetPath,
                items: this.latestActionableItems,
            });
        }

        if (!(looksLikeFixRequest(prompt) || looksLikeImplementRequest(prompt) || looksLikeFindingFollowUp(prompt))) {
            return undefined;
        }

        const finding = suggestedFinding ?? this.latestActionableFinding;
        const targetPath = this.getActiveFixTargetPath();
        if (suggestedFinding) {
            if (!finding || !targetPath) {
                return undefined;
            }
            return [buildReviewFixAction(finding, targetPath)];
        }

        if (this.latestActionableItems.length) {
            const batchAction = buildBatchReviewFixAction(this.latestActionableItems);
            return batchAction ? [batchAction] : undefined;
        }

        if (!finding || !targetPath) {
            return undefined;
        }

        return [buildReviewFixAction(finding, targetPath)];
    }

    private async handleScanFileIntent(intent: ChatLocalIntent): Promise<LocalActionResult> {
        const targetUri = intent.fileHint
            ? await this.resolveFileIntentTarget(intent.fileHint)
            : undefined;
        const result = await vscode.commands.executeCommand<any>(PROFILE.commands.scanFile, targetUri);

        if (result?.status === 'cancelled') {
            return {
                handled: true,
                response: targetUri
                    ? `File scan was cancelled for ${path.basename(targetUri.fsPath)}.`
                    : 'File scan was cancelled.',
                kind: 'scan',
            };
        }

        if (!result?.result) {
            return { handled: true, response: 'File scan did not complete.', kind: 'scan' };
        }

        const relativePath = result.uri
            ? vscode.workspace.asRelativePath(result.uri, false)
            : (intent.fileHint ?? 'the selected file');
        this.latestActionableFinding = result.result.findings
            .slice()
            .sort((left: Finding, right: Finding) => riskRank(right) - riskRank(left))[0];
        this.latestActionableTargetPath = result.uri?.fsPath;
        this.latestActionableItems = this.latestActionableFinding && result.uri
            ? [{ finding: this.latestActionableFinding, targetPath: result.uri.fsPath }]
            : [];
        const actions: ChatMessageAction[] = result.uri
            ? [buildExplainScoreAction('explain-score-scan-file-intent', [{ uri: result.uri, result: result.result }])]
            : [];
        actions.unshift(...buildPrimaryFixAction(this.latestActionableItems));
        return {
            handled: true,
            response: [
                `File scan completed for ${relativePath}.`,
                ...buildScanSummaryLines(result.result),
                this.latestActionableFinding ? 'Next step: use Preview fix to open a side-by-side remediation diff.' : '',
            ].join('\n'),
            kind: 'scan',
            actions,
        };
    }

    private buildState(
        models: string[],
        providers: Array<{ id: string; name: string }>,
        providerStatus: string,
        providerHint: string,
        backendStatus: string,
        licenceStatus: string,
        providerConfigured = false,
        hasLicence = false,
        hasStoredLicenceKey = false,
    ): ChatState {
        const editorContext = this.buildEditorContext();
        const provider = this.registry.getActive();
        const projectContextSummary = getProjectContextSummaryFromConfig();
        const workingScope = this.getWorkingScope();
        return {
            provider: provider.name,
            providerId: provider.id,
            model: provider.selectedModel,
            models,
            providers,
            providerStatus,
            providerHint,
            providerConfigured,
            backendStatus,
            licenceStatus,
            hasLicence,
            hasStoredLicenceKey,
            messages: this.messages,
            editorSummary: editorContext.summary,
            frameworksLabel: formatFrameworkSummary(this.getFrameworks()),
            severityThreshold: this.getSeverityThreshold(),
            projectContextSummary,
            workspaceSummary: this.getWorkspaceSummary(),
            lastScanTarget: this.storage.get<string>(LAST_SCAN_TARGET_KEY, 'No scan run yet'),
            hasLastScan: this.storage.get<string>(LAST_SCAN_TARGET_KEY, 'No scan run yet') !== 'No scan run yet',
            conversationStatus: buildConversationStatus({
                pendingFixPreview: this.pendingFixPreview,
                latestActionableFinding: this.latestActionableFinding,
                latestActionableTargetPath: this.latestActionableTargetPath,
            }),
            hasRestorableChat: Boolean(this.restorableMessages?.length),
            restorableMessageCount: Math.max(0, (this.restorableMessages?.length ?? 0) - 1),
            workingScope,
            workingScopeLabel: getWorkingScopeLabel(workingScope),
            activeMode: this.currentMode,
            activeModeLabel: getConversationModeLabel(this.currentMode),
            activeModeHint: getConversationModeHint(this.currentMode),
        };
    }

    private postState(state: ChatState): void {
        this.view?.webview.postMessage({
            type: 'chat:state',
            ...state,
        });
    }

    private getFallbackModels(): string[] {
        const provider = this.registry.getActive();
        return provider.selectedModel ? [provider.selectedModel] : [];
    }

    private async pushResolvedState(): Promise<void> {
        const configuredProviders = await this.getConfiguredProviders();
        const provider = this.registry.getActive();
        const activeProviderConfigured = configuredProviders.some(item => item.id === provider.id);

        const models = await this.getModelsForProvider(provider);
        const providerStatus = activeProviderConfigured
            ? `LLM status: ${provider.name} is configured`
            : configuredProviders.length
                ? `LLM status: ${provider.name} is selected but not configured`
                : 'LLM status: no provider configured';
        const providerHint = configuredProviders.length
            ? activeProviderConfigured
                ? 'Configured providers only are shown here.'
                : `${provider.name} is selected but not configured. Finish configuring it or switch to another configured provider.`
            : `${getProviderSetupHint(provider.id)} Use "Configure LLM" to add your first provider.`;
        const configuredApiUrl = vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('apiUrl', PROFILE.defaultApiUrl) || PROFILE.defaultApiUrl;
        const backendStatus = `Backend: ${configuredApiUrl}`;
        const licenceKey = await this.licenceMgr.getKey().catch(() => undefined);
        const cachedLicence = this.licenceMgr.getCachedInfo();
        const licenceStatus = cachedLicence
            ? buildLicenceStatusSummary(cachedLicence)
            : licenceKey
                ? 'Licence: key stored, validation pending'
                : 'Licence: not connected';
        const visibleProviders = (() => {
            const all = activeProviderConfigured
                ? configuredProviders
                : [{ id: provider.id, name: provider.name }, ...configuredProviders];
            return [...new Map(all.map(item => [item.id, item])).values()];
        })();
        this.postState(this.buildState(
            models,
            visibleProviders,
            providerStatus,
            providerHint,
            backendStatus,
            licenceStatus,
            activeProviderConfigured,
            Boolean(cachedLicence),
            Boolean(licenceKey),
        ));
    }

    private async getModelsForProvider(provider: ReturnType<ProviderRegistry['getActive']>): Promise<string[]> {
        try {
            const models = await provider.listModels();
            if (models.length) return models;
        } catch {
            // Ignore list failures and fall back to current model.
        }
        return [provider.selectedModel];
    }

    private async getConfiguredProviders(): Promise<Array<{ id: string; name: string }>> {
        const allProviders = this.registry.allProviders();
        const configured = await Promise.all(allProviders.map(async (provider) => ({
            id: provider.id,
            name: provider.name,
            configured: await provider.isConfigured().catch(() => false),
        })));

        return configured
            .filter(item => item.configured)
            .map(({ id, name }) => ({ id, name }));
    }

    private async resolveFileIntentTarget(fileHint: string): Promise<vscode.Uri | undefined> {
        const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
        if (!workspaceFolders.length) return undefined;

        const candidates: Array<{ uri: vscode.Uri; score: number }> = [];
        for (const folder of workspaceFolders) {
            const files = await collectScannableFiles(folder.uri, 300);
            for (const uri of files) {
                const score = scoreFileMatch(fileHint, uri);
                if (score > 0) {
                    candidates.push({ uri, score });
                }
            }
        }

        candidates.sort((left, right) => right.score - left.score);
        return candidates[0]?.uri;
    }

    private async buildWorkingScopeContext(scope: WorkingScope, promptForRepoTarget?: string): Promise<EditorContext> {
        switch (scope) {
            case 'scanFile':
                return this.buildEditorContext();
            case 'scanOpenEditors':
                return this.buildOpenEditorsContext();
            case 'scanSelectedFiles':
                return this.buildSelectedFilesContext();
            case 'scanFolder':
            default:
                return this.buildWorkspaceRepoContext(promptForRepoTarget);
        }
    }

    private async buildRepoAwareWorkingScopeContext(scope: WorkingScope, promptForRepoTarget: string): Promise<EditorContext> {
        const repoContext = await this.buildWorkspaceRepoContext(promptForRepoTarget);
        if (scope === 'scanFolder') {
            return repoContext;
        }

        const scopedContext = await this.buildWorkingScopeContext(scope);
        return {
            summary: [
                repoContext.summary,
                scopedContext.summary,
            ].filter(Boolean).join('; '),
            promptContext: [
                repoContext.promptContext,
                'Additional working-scope code context:',
                scopedContext.promptContext,
            ].join('\n\n'),
        };
    }

    private buildEditorContext(): EditorContext {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return {
                summary: 'Active editor: none',
                promptContext: 'No active editor is open.',
            };
        }

        const doc = editor.document;
        const relativePath = vscode.workspace.asRelativePath(doc.uri, false);
        const selectionText = editor.selection.isEmpty ? '' : doc.getText(editor.selection);
        const fullText = doc.getText();
        const trimmedFileText = fullText.length > 12000
            ? `${fullText.slice(0, 12000)}\n\n[truncated after 12000 characters]`
            : fullText;
        const trimmedSelection = selectionText.length > 4000
            ? `${selectionText.slice(0, 4000)}\n\n[selection truncated after 4000 characters]`
            : selectionText;

        return {
            summary: selectionText
                ? `Active editor: ${relativePath} with a code selection`
                : `Active editor: ${relativePath}`,
            promptContext: [
                `Active file: ${relativePath}`,
                `Language: ${doc.languageId}`,
                selectionText
                    ? `Selected code:\n${trimmedSelection}`
                    : 'Selected code: none',
                `Current file excerpt:\n${trimmedFileText}`,
            ].join('\n\n'),
        };
    }

    private async buildOpenEditorsContext(): Promise<EditorContext> {
        const editors = vscode.window.visibleTextEditors
            .map(editor => editor.document)
            .filter(document => Boolean(document?.uri?.fsPath))
            .filter((document, index, all) => all.findIndex(item => item.uri.fsPath === document.uri.fsPath) === index)
            .slice(0, 4);

        if (!editors.length) {
            return {
                summary: 'Working scope: Open editors (none available)',
                promptContext: 'Working scope: Open editors\nNo open editors are available for AI context.',
            };
        }

        return {
            summary: `Working scope: Open editors (${editors.length} file${editors.length === 1 ? '' : 's'})`,
            promptContext: [
                `Working scope: Open editors`,
                ...editors.map(document => {
                    const relativePath = vscode.workspace.asRelativePath(document.uri, false);
                    const fullText = document.getText();
                    const excerpt = fullText.length > 4000
                        ? `${fullText.slice(0, 4000)}\n\n[truncated after 4000 characters]`
                        : fullText;
                    return [
                        `Open editor: ${relativePath}`,
                        `Language: ${document.languageId}`,
                        `Excerpt:\n${excerpt}`,
                    ].join('\n');
                }),
            ].join('\n\n'),
        };
    }

    private async buildSelectedFilesContext(): Promise<EditorContext> {
        const uniquePaths = [...new Set(this.lastSelectedScopePaths.map(item => path.normalize(item)))].slice(0, 4);
        if (!uniquePaths.length) {
            const fallback = this.buildEditorContext();
            return {
                summary: 'Working scope: Selected files (no selected-file batch available, falling back to current file)',
                promptContext: [
                    'Working scope: Selected files',
                    'Selected-file context is not yet available in chat because no selected-files batch has been scanned in this session.',
                    fallback.promptContext,
                ].join('\n\n'),
            };
        }

        const documents = await Promise.all(uniquePaths.map(async filePath => {
            try {
                return await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
            } catch {
                return undefined;
            }
        }));

        const availableDocs = documents.filter((doc): doc is vscode.TextDocument => Boolean(doc)).slice(0, 4);
        if (!availableDocs.length) {
            return {
                summary: 'Working scope: Selected files (files unavailable)',
                promptContext: 'Working scope: Selected files\nThe last selected-file batch is no longer available on disk.',
            };
        }

        return {
            summary: `Working scope: Selected files (${availableDocs.length} file${availableDocs.length === 1 ? '' : 's'})`,
            promptContext: [
                'Working scope: Selected files',
                ...availableDocs.map(document => {
                    const relativePath = vscode.workspace.asRelativePath(document.uri, false);
                    const fullText = document.getText();
                    const excerpt = fullText.length > 4000
                        ? `${fullText.slice(0, 4000)}\n\n[truncated after 4000 characters]`
                        : fullText;
                    return [
                        `Selected file: ${relativePath}`,
                        `Language: ${document.languageId}`,
                        `Excerpt:\n${excerpt}`,
                    ].join('\n');
                }),
            ].join('\n\n'),
        };
    }

    private async buildWorkspaceRepoContext(promptForRepoTarget?: string): Promise<EditorContext> {
        const projectRoot = await resolveProjectRootInfo();
        const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
        const scopeRoots: RepoScopeRoot[] = projectRoot.uri
            ? [{ uri: projectRoot.uri, label: projectRoot.label }]
            : workspaceFolders.map(folder => ({ uri: folder.uri, label: folder.name }));

        if (!scopeRoots.length) {
            return {
                summary: 'Working scope: Workspace (no project root selected)',
                promptContext: 'Working scope: Workspace\nNo project root is configured and no workspace folder is open.',
            };
        }

        if (promptForRepoTarget && looksLikeRepoQuestion(promptForRepoTarget)) {
            const targetMatches = (await Promise.all(scopeRoots.slice(0, 3).map(folder => collectWorkspaceDirectoryCandidates(folder, promptForRepoTarget))))
                .flat()
                .sort((left, right) =>
                    right.score - left.score
                    || right.label.length - left.label.length
                    || left.label.localeCompare(right.label),
                );
            const bestMatch = targetMatches[0];
            if (bestMatch && bestMatch.score >= 6) {
                let entries: Array<[string, vscode.FileType]> = [];
                try {
                    entries = await vscode.workspace.fs.readDirectory(bestMatch.uri);
                } catch {
                    entries = [];
                }
                const visibleEntries = entries
                    .filter(([name]) => !name.startsWith('.'))
                    .slice(0, 12)
                    .map(([name, fileType]) => `${name}${fileType === vscode.FileType.Directory ? '/' : ''}`);

                const readmeUri = vscode.Uri.joinPath(bestMatch.uri, 'README.md');
                const packageUri = vscode.Uri.joinPath(bestMatch.uri, 'package.json');
                const readme = await tryReadWorkspaceFile(readmeUri);
                const packageJson = await tryReadWorkspaceFile(packageUri);
                let mainSection: string | undefined;
                if (packageJson) {
                    try {
                        const parsed = JSON.parse(packageJson) as { main?: string; scripts?: Record<string, string>; description?: string };
                        const mainFile = typeof parsed.main === 'string' && parsed.main.trim() ? parsed.main.trim() : undefined;
                        if (mainFile) {
                            const mainUri = vscode.Uri.joinPath(bestMatch.uri, ...mainFile.split(/[\\/]+/g));
                            const mainContent = await tryReadWorkspaceFile(mainUri);
                            if (mainContent !== undefined) {
                                const excerpt = mainContent.length > 3000
                                    ? `${mainContent.slice(0, 3000)}\n\n[truncated after 3000 characters]`
                                    : mainContent;
                                mainSection = `${mainFile}:\n${excerpt}`;
                            }
                        }
                    } catch {
                        // Ignore malformed package.json during repo summary.
                    }
                }

                return {
                    summary: `Working scope: Workspace (targeted module ${bestMatch.label})`,
                    promptContext: [
                        'Working scope: Workspace',
                        `Selected project root: ${projectRoot.label}`,
                        `Targeted repo focus: ${bestMatch.label}`,
                        'Owlvex may use the full selected project root as context, but should keep this targeted module as the primary interpretation target.',
                        `Module path: ${bestMatch.label}`,
                        visibleEntries.length ? `Module entries: ${visibleEntries.join(', ')}` : 'Module entries: unavailable',
                        readme ? `README.md:\n${readme.length > 3000 ? `${readme.slice(0, 3000)}\n\n[truncated after 3000 characters]` : readme}` : '',
                        packageJson ? `package.json:\n${packageJson.length > 3000 ? `${packageJson.slice(0, 3000)}\n\n[truncated after 3000 characters]` : packageJson}` : '',
                        mainSection ?? '',
                    ].filter(Boolean).join('\n\n'),
                };
            }
        }

        const rootSections = await Promise.all(scopeRoots.slice(0, 3).map(async folder => {
            let entries: Array<[string, vscode.FileType]> = [];
            try {
                entries = await vscode.workspace.fs.readDirectory(folder.uri);
            } catch {
                entries = [];
            }
            const visibleEntries = entries
                .filter(([name]) => !name.startsWith('.'))
                .slice(0, 12)
                .map(([name, fileType]) => `${name}${fileType === vscode.FileType.Directory ? '/' : ''}`);

            const keyFileSections = await Promise.all(WORKSPACE_CONTEXT_FILES.map(async fileName => {
                const target = vscode.Uri.joinPath(folder.uri, fileName);
                const content = await tryReadWorkspaceFile(target);
                if (content === undefined) {
                    return undefined;
                }
                const excerpt = content.length > 3000
                    ? `${content.slice(0, 3000)}\n\n[truncated after 3000 characters]`
                    : content;
                return `${fileName}:\n${excerpt}`;
            }));

            return [
                `Project root: ${folder.label}`,
                visibleEntries.length ? `Top-level entries: ${visibleEntries.join(', ')}` : 'Top-level entries: unavailable',
                ...keyFileSections.filter((section): section is string => Boolean(section)),
            ].join('\n\n');
        }));

        return {
            summary: `Working scope: Workspace (${scopeRoots.map(folder => folder.label).join(', ')})`,
            promptContext: [
                'Working scope: Workspace',
                `Selected project root: ${projectRoot.label}`,
                'AI may use the full selected project root, including repo-level structure and key root files, but should stay inside this project boundary.',
                ...rootSections,
            ].join('\n\n'),
        };
    }

    private buildScanContext(scope: WorkingScope): EditorContext {
        const frameworks = this.getFrameworks();
        const severity = this.getSeverityThreshold();
        const projectContextSummary = getProjectContextSummaryFromConfig();

        return {
            summary: `Active scan profile: scope=${getWorkingScopeLabel(scope)}, frameworks=${frameworks.join(', ') || 'none'}, severity threshold=${severity}`,
            promptContext: [
                `Working scope: ${getWorkingScopeLabel(scope)}`,
                `Security frameworks in scope: ${frameworks.join(', ') || 'none configured'}`,
                `Severity threshold: ${severity}`,
                projectContextSummary !== 'none'
                    ? `Project context contract available: ${projectContextSummary}`
                    : 'Project context contract: none',
            ].join('\n'),
        };
    }

    private getFrameworks(): string[] {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string[]>('frameworks', ['OWASP', 'STRIDE']);
    }

    private getSeverityThreshold(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('severityThreshold', 'MEDIUM');
    }

    private getWorkspaceSummary(): string {
        const projectRoot = getProjectRootSummaryFromConfig();
        if (projectRoot !== 'not set') {
            return `Project root: ${projectRoot}`;
        }

        const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
        if (!workspaceFolders.length) return 'No workspace folder open';
        return `Default workspace: ${workspaceFolders.map(folder => folder.name).join(', ')}`;
    }

    private buildHtml(): string {
        const nonce = getNonce();

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
  <style>
    body {
      margin: 0;
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
    }
    .shell {
      display: flex;
      flex-direction: column;
      height: 100vh;
    }
    .header {
      padding: 12px 14px;
      border-bottom: 1px solid var(--vscode-sideBarSectionHeader-border);
      background: linear-gradient(135deg, var(--vscode-editorWidget-background), var(--vscode-sideBar-background));
    }
    .header-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .title {
      font-size: 13px;
      font-weight: 700;
    }
    .topbar-title {
      display: flex;
      flex-direction: column;
      gap: 2px;
      min-width: 0;
    }
    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-shrink: 0;
    }
    .subtitle {
      font-size: 11px;
      opacity: 0.76;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .meta {
      margin-top: 4px;
      font-size: 11px;
      opacity: 0.75;
      line-height: 1.35;
    }
    .meta.compact {
      margin-top: 6px;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-top: 8px;
    }
    .summary-card {
      border: 1px solid var(--vscode-widget-border);
      border-radius: 10px;
      padding: 7px 10px;
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 82%, transparent);
    }
    .summary-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      opacity: 0.68;
    }
    .summary-value {
      margin-top: 3px;
      font-size: 11px;
      line-height: 1.35;
    }
    .icon-button {
      border: 1px solid var(--vscode-widget-border);
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 72%, transparent);
      color: var(--vscode-foreground);
      border-radius: 999px;
      width: 28px;
      height: 28px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0;
      font-size: 14px;
      line-height: 1;
      cursor: pointer;
    }
    .icon-button[disabled] {
      opacity: 0.45;
      cursor: default;
    }
    .settings-close {
      width: 24px;
      height: 24px;
      padding: 0;
      border-radius: 999px;
      border: 1px solid var(--vscode-widget-border);
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 72%, transparent);
      color: var(--vscode-foreground);
      cursor: pointer;
    }
    .settings-panel {
      margin-top: 8px;
      border: 1px solid var(--vscode-widget-border);
      border-radius: 12px;
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 85%, transparent);
      overflow: hidden;
    }
    .settings-head {
      padding: 10px 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      font-size: 11px;
      font-weight: 600;
      border-bottom: 1px solid var(--vscode-widget-border);
    }
    .settings-status {
      font-size: 10px;
      font-weight: 500;
      opacity: 0.8;
    }
    .settings-body {
      padding: 10px 12px 12px;
    }
    .controls {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-top: 0;
    }
    .quick-actions {
      display: flex;
      gap: 8px;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    .quick-actions details {
      position: relative;
    }
    .quick-actions summary {
      list-style: none;
    }
    .quick-actions summary::-webkit-details-marker {
      display: none;
    }
    .more-actions-panel {
      margin-top: 8px;
      padding-top: 8px;
      border-top: 1px solid color-mix(in srgb, var(--vscode-widget-border) 80%, transparent);
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .chip {
      border: 1px solid var(--vscode-button-border, var(--vscode-widget-border));
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border-radius: 999px;
      padding: 6px 10px;
      font: inherit;
      font-size: 11px;
      cursor: pointer;
    }
    select {
      width: 100%;
      box-sizing: border-box;
      border-radius: 8px;
      padding: 8px 10px;
      color: var(--vscode-input-foreground);
      background: var(--vscode-dropdown-background);
      border: 1px solid var(--vscode-dropdown-border);
      font: inherit;
    }
    .conversation {
      flex: 1 1 auto;
      display: flex;
      flex-direction: column;
      min-height: 260px;
      resize: vertical;
      overflow: auto;
      border-top: 1px solid var(--vscode-sideBarSectionHeader-border);
      border-bottom: 1px solid var(--vscode-sideBarSectionHeader-border);
      background: color-mix(in srgb, var(--vscode-editor-background) 30%, var(--vscode-sideBar-background));
    }
    .history-strip {
      display: none;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 9px 14px;
      font-size: 11px;
      border-bottom: 1px solid color-mix(in srgb, var(--vscode-sideBarSectionHeader-border) 70%, transparent);
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 34%, transparent);
    }
    .history-strip.visible {
      display: flex;
    }
    .history-strip[hidden] {
      display: none !important;
    }
    .history-copy {
      opacity: 0.78;
    }
    .history-actions {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .link-button {
      border: none;
      background: transparent;
      color: var(--vscode-textLink-foreground);
      padding: 0;
      font: inherit;
      cursor: pointer;
    }
    .conversation-header {
      padding: 9px 14px;
      font-size: 11px;
      opacity: 0.72;
      border-bottom: 1px solid color-mix(in srgb, var(--vscode-sideBarSectionHeader-border) 70%, transparent);
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 52%, transparent);
    }
    .mode-row {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 9px 14px 0;
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
    }
    .mode-badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
      font-weight: 600;
    }
    .mode-hint {
      opacity: 0.86;
    }
    .messages {
      flex: 1 1 auto;
      overflow-y: auto;
      padding: 16px 14px 18px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .msg {
      max-width: 100%;
      padding: 11px 12px;
      border-radius: 14px;
      line-height: 1.5;
      word-break: break-word;
      font-size: 12px;
      box-sizing: border-box;
    }
    .msg-body {
      white-space: pre-wrap;
    }
    .msg-body + .msg-actions {
      margin-top: 10px;
    }
    .tag {
      display: inline-block;
      margin-bottom: 7px;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 10px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      opacity: 0.9;
    }
    .tag.advisory {
      background: color-mix(in srgb, var(--vscode-textLink-foreground) 18%, transparent);
      color: var(--vscode-textLink-foreground);
    }
    .tag.scan {
      background: color-mix(in srgb, var(--vscode-testing-iconPassed) 22%, transparent);
      color: var(--vscode-testing-iconPassed);
    }
    .msg-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 10px;
    }
    .msg-action {
      border: 1px solid var(--vscode-button-border, var(--vscode-widget-border));
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 55%, transparent);
      color: var(--vscode-textLink-foreground);
      border-radius: 999px;
      padding: 5px 9px;
      font-size: 11px;
    }
    .msg.user {
      align-self: flex-end;
      max-width: 88%;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      box-shadow: 0 2px 8px color-mix(in srgb, var(--vscode-button-background) 18%, transparent);
    }
    .msg.assistant, .msg.system {
      align-self: flex-start;
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-widget-border);
      box-shadow: 0 1px 5px color-mix(in srgb, var(--vscode-editorWidget-background) 14%, transparent);
    }
    .empty-state {
      border: 1px solid var(--vscode-widget-border);
      border-radius: 12px;
      padding: 14px;
      background: var(--vscode-editorWidget-background);
      display: grid;
      gap: 12px;
    }
    .empty-title {
      font-size: 13px;
      font-weight: 700;
    }
    .empty-copy {
      font-size: 12px;
      line-height: 1.45;
      opacity: 0.86;
    }
    .setup-list {
      display: grid;
      gap: 7px;
    }
    .setup-row {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
    }
    .setup-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--vscode-charts-orange);
      flex: 0 0 auto;
    }
    .setup-row.ready .setup-dot {
      background: var(--vscode-testing-iconPassed);
    }
    .empty-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .empty-actions button {
      border: 1px solid var(--vscode-button-border, var(--vscode-widget-border));
      border-radius: 999px;
      padding: 7px 10px;
      font-size: 11px;
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    .empty-actions button.primary-action {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
    }
    .composer {
      border-top: 1px solid var(--vscode-sideBarSectionHeader-border);
      padding: 12px;
      display: grid;
      gap: 9px;
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 40%, transparent);
    }
    .action-rail {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .rail-chip,
    .rail-select,
    .rail-button {
      border: 1px solid var(--vscode-widget-border);
      background: color-mix(in srgb, var(--vscode-editorWidget-background) 72%, transparent);
      color: var(--vscode-foreground);
      border-radius: 999px;
      min-height: 32px;
      padding: 0 10px;
      font: inherit;
      font-size: 11px;
    }
    .rail-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
    }
    .rail-select {
      width: auto;
      min-width: 124px;
      padding-right: 26px;
      box-sizing: border-box;
    }
    .rail-button {
      cursor: pointer;
    }
    .llm-menu,
    .report-menu {
      position: relative;
    }
    .llm-menu summary,
    .report-menu summary {
      list-style: none;
      cursor: pointer;
    }
    .llm-menu summary::-webkit-details-marker,
    .report-menu summary::-webkit-details-marker {
      display: none;
    }
    .llm-menu-panel,
    .report-menu-panel {
      position: absolute;
      left: 0;
      bottom: calc(100% + 8px);
      z-index: 20;
      border: 1px solid var(--vscode-widget-border);
      border-radius: 12px;
      background: var(--vscode-editorWidget-background);
      box-shadow: 0 8px 24px color-mix(in srgb, var(--vscode-editor-background) 28%, transparent);
      padding: 10px;
      display: grid;
      gap: 8px;
    }
    .llm-menu-panel {
      width: 260px;
    }
    .report-menu-panel {
      width: 190px;
    }
    .llm-menu-panel .meta {
      margin-top: 0;
    }
    .report-option {
      width: 100%;
      text-align: left;
    }
    .composer-hint {
      font-size: 11px;
      opacity: 0.7;
    }
    textarea {
      width: 100%;
      min-height: 84px;
      resize: vertical;
      box-sizing: border-box;
      border-radius: 12px;
      padding: 11px 12px;
      color: var(--vscode-input-foreground);
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border);
      font: inherit;
    }
    .actions {
      display: flex;
      gap: 8px;
      justify-content: flex-end;
    }
    button {
      border: none;
      border-radius: 8px;
      padding: 8px 12px;
      font: inherit;
      cursor: pointer;
    }
    button.primary {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
    }
    button.secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="header">
      <div class="header-top">
        <div class="topbar-title">
          <div class="title">Owlvex</div>
          <div class="subtitle" id="assistantCaptionBar">Provider: connecting...</div>
        </div>
        <div class="topbar-actions">
          <button class="icon-button" id="toggleHistory" type="button" title="Chat history" aria-label="Chat history">&#8634;</button>
          <button class="icon-button" id="toggleSettingsTop" type="button" title="Settings" aria-label="Open settings">&#9881;</button>
          <button class="icon-button" id="newChatTop" type="button" title="New chat" aria-label="New chat">&#9998;</button>
        </div>
      </div>
      <div class="settings-panel" id="settingsPanel" hidden>
        <div class="settings-head">
          <span>Configuration</span>
          <div style="display:flex;align-items:center;gap:8px;">
            <span class="settings-status" id="providerStatus">LLM status: checking...</span>
            <button class="settings-close" id="closeSettings" type="button" aria-label="Close settings">&times;</button>
          </div>
        </div>
        <div class="settings-body">
          <div class="meta" id="backendStatus">Backend: loading...</div>
          <div class="meta" id="licenceStatus">Licence: loading...</div>
          <div class="meta" id="workspaceDetail">Workspace: loading...</div>
          <div class="meta" id="editor">Inspecting editor...</div>
          <div class="meta" id="projectContext">Project context: loading...</div>
          <div class="quick-actions">
            <button class="chip" data-action="showOnboarding">Onboarding</button>
            <button class="chip" data-auth-action data-action="useFree">Use Free</button>
            <button class="chip" data-auth-action data-action="startTrial">Start Trial</button>
            <button class="chip" data-action="selectProjectRoot">Project Root</button>
            <button class="chip" data-action="testAI">Test Connection</button>
            <button class="chip" data-action="selectFrameworks">Select Frameworks</button>
            <details>
              <summary class="chip">More</summary>
              <div class="more-actions-panel">
                <button class="chip" data-action="enterLicence">Enter Licence</button>
                <button class="chip" data-action="viewPlans">View Plans</button>
                <button class="chip" data-action="testTrialSetup">Test Trial Setup</button>
                <button class="chip" data-action="reviewRiskCalibration">Review Scores</button>
                <button class="chip" data-action="securityBoundary">Security Boundary</button>
                <button class="chip" data-action="toggleTelemetry">Telemetry</button>
                <button class="chip" data-action="configureBackend">Backend Override</button>
              </div>
            </details>
          </div>
        </div>
      </div>
    </div>
    <div class="conversation" id="conversation">
      <div class="history-strip" id="historyStrip" hidden>
        <div class="history-copy" id="historyCopy">Previous chat available.</div>
        <div class="history-actions">
          <button class="link-button" id="restorePrevious">Restore previous chat</button>
          <button class="link-button" id="dismissHistory">Hide</button>
        </div>
      </div>
      <div class="mode-row">
        <span class="mode-badge" id="modeBadge">Mode: General</span>
        <span class="mode-hint" id="modeHint">General behavior: free-form help without implicit scan or repo-grounded claims.</span>
      </div>
      <div class="conversation-header" id="conversationHeader">Conversation. Ask follow-up questions, open a fix preview, or keep working from the latest finding.</div>
      <div class="messages" id="messages"></div>
    </div>
    <div class="composer">
      <div class="action-rail">
        <details class="llm-menu" id="llmMenu">
          <summary class="rail-button" id="llmButton">LLM: connecting...</summary>
          <div class="llm-menu-panel">
            <div class="meta" id="providerHint">LLM setup hint: loading...</div>
            <select id="provider"></select>
            <select id="model"></select>
            <button class="rail-button" data-action="setupAI">Configure LLM</button>
          </div>
        </details>
        <select id="scanScopeBottom" class="rail-select" aria-label="Scan scope">
          <option value="scanFile">Current file</option>
          <option value="scanSelectedFiles">Selected files</option>
          <option value="scanOpenEditors">Open editors</option>
          <option value="scanFolder" selected>Workspace</option>
        </select>
        <button class="rail-button" id="runScanBottom" type="button">Scan</button>
        <details class="report-menu" id="reportMenu">
          <summary class="rail-button" id="reportButton">Report</summary>
          <div class="report-menu-panel">
            <button class="rail-button report-option" data-action="scanSummaryReport" type="button">Summary report</button>
            <button class="rail-button report-option" data-action="scanFullReport" type="button">Full evidence report</button>
          </div>
        </details>
      </div>
      <div class="composer-hint">Press <strong>Enter</strong> to send, <strong>Shift+Enter</strong> for a new line.</div>
      <textarea id="prompt" placeholder="Ask Owlvex about this repo, a vulnerability, or what to scan next."></textarea>
      <div class="actions">
        <button class="primary" id="send">Send</button>
      </div>
    </div>
  </div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const messagesEl = document.getElementById('messages');
    const assistantCaptionBarEl = document.getElementById('assistantCaptionBar');
    const promptEl = document.getElementById('prompt');
    const workspaceDetailEl = document.getElementById('workspaceDetail');
    const editorEl = document.getElementById('editor');
    const projectContextEl = document.getElementById('projectContext');
    const providerStatusEl = document.getElementById('providerStatus');
    const backendStatusEl = document.getElementById('backendStatus');
    const licenceStatusEl = document.getElementById('licenceStatus');
    const providerHintEl = document.getElementById('providerHint');
    const conversationHeaderEl = document.getElementById('conversationHeader');
    const modeBadgeEl = document.getElementById('modeBadge');
    const modeHintEl = document.getElementById('modeHint');
    const scanScopeBottomEl = document.getElementById('scanScopeBottom');
    const runScanBottomEl = document.getElementById('runScanBottom');
    const reportMenuEl = document.getElementById('reportMenu');
    const providerEl = document.getElementById('provider');
    const modelEl = document.getElementById('model');
    const settingsPanelEl = document.getElementById('settingsPanel');
    const historyStripEl = document.getElementById('historyStrip');
    const historyCopyEl = document.getElementById('historyCopy');
    const toggleSettingsTopEl = document.getElementById('toggleSettingsTop');
    const closeSettingsEl = document.getElementById('closeSettings');
    const toggleHistoryEl = document.getElementById('toggleHistory');
    const restorePreviousEl = document.getElementById('restorePrevious');
    const dismissHistoryEl = document.getElementById('dismissHistory');
    const newChatTopEl = document.getElementById('newChatTop');
    const llmButtonEl = document.getElementById('llmButton');
    const reportButtonEl = document.getElementById('reportButton');
    let historyVisible = false;

    function postAction(action) {
      vscode.postMessage({ type: 'chat:action', action });
    }

    function appendEmptyState(state) {
      const card = document.createElement('div');
      card.className = 'empty-state';

      const title = document.createElement('div');
      title.className = 'empty-title';
      title.textContent = 'Start in 60 seconds';
      card.appendChild(title);

      const copy = document.createElement('div');
      copy.className = 'empty-copy';
      copy.textContent = state.hasLicence
        ? 'Run a first scan, then use the summary report or fix preview from the scan result.'
        : 'Connect access first, then scan the current file or workspace. LLM setup unlocks AI review and fix previews.';
      card.appendChild(copy);

      const list = document.createElement('div');
      list.className = 'setup-list';
      const rows = [
        ['Access', state.hasLicence ? state.licenceStatus : state.hasStoredLicenceKey ? 'Key stored, validation pending' : 'Choose Free, Trial, or enter a licence', state.hasLicence],
        ['Project', state.workspaceSummary || 'No workspace folder open', Boolean(state.workspaceSummary && state.workspaceSummary !== 'No workspace folder open')],
        ['LLM', state.providerConfigured ? state.provider + ' configured' : 'Configure when you want AI review', state.providerConfigured],
        ['First scan', state.hasLastScan ? state.lastScanTarget : 'Not run yet', state.hasLastScan],
      ];
      for (const row of rows) {
        const item = document.createElement('div');
        item.className = 'setup-row' + (row[2] ? ' ready' : '');
        const dot = document.createElement('span');
        dot.className = 'setup-dot';
        const text = document.createElement('span');
        text.textContent = row[0] + ': ' + row[1];
        item.appendChild(dot);
        item.appendChild(text);
        list.appendChild(item);
      }
      card.appendChild(list);

      const actions = document.createElement('div');
      actions.className = 'empty-actions';
      const addAction = (label, action, primary) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = label;
        if (primary) button.className = 'primary-action';
        button.addEventListener('click', () => postAction(action));
        actions.appendChild(button);
      };

      if (!state.hasLicence) {
        addAction('Use Free', 'useFree', true);
        addAction('Start Trial', 'startTrial', false);
        addAction('Enter Licence', 'enterLicence', false);
      } else if (!state.hasLastScan) {
        addAction(state.workingScope === 'scanFile' ? 'Scan Current File' : 'Scan Workspace', state.workingScope || 'scanFolder', true);
      } else {
        addAction('Summary Report', 'scanSummaryReport', true);
      }
      if (!state.providerConfigured) {
        addAction('Configure LLM', 'setupAI', false);
      }
      addAction('Onboarding Check', 'showOnboarding', false);

      card.appendChild(actions);
      messagesEl.appendChild(card);
    }

    function render(state) {
      const providerLine = 'Provider: ' + state.provider + ' | Model: ' + state.model;
      assistantCaptionBarEl.textContent = providerLine;
      workspaceDetailEl.textContent = 'Workspace: ' + (state.workspaceSummary || 'No workspace folder open');
      editorEl.textContent = state.editorSummary || 'Active editor: none';
      projectContextEl.textContent = 'Project context: ' + (state.projectContextSummary || 'none');
      providerStatusEl.textContent = state.providerStatus || 'LLM status: unknown';
      backendStatusEl.textContent = state.backendStatus || 'Backend: unknown';
      licenceStatusEl.textContent = state.licenceStatus || 'Licence: unknown';
      providerHintEl.textContent = state.providerHint || '';
      llmButtonEl.textContent = state.providerConfigured
        ? state.provider + ' · ' + state.model
        : 'Configure LLM';
      if (reportButtonEl) {
        reportButtonEl.textContent = state.hasLastScan ? 'Report' : 'Report after scan';
        reportButtonEl.title = state.hasLastScan ? 'Create a report' : 'Run a scan first, or choose a report action to scan and report.';
      }
      modeBadgeEl.textContent = 'Mode: ' + (state.activeModeLabel || 'General');
      modeHintEl.textContent = state.activeModeHint || '';
      conversationHeaderEl.textContent = state.conversationStatus || 'Conversation. Ask follow-up questions, open a fix preview, or keep working from the latest finding.';
      if (scanScopeBottomEl && state.workingScope) {
        scanScopeBottomEl.value = state.workingScope;
      }
      if (settingsPanelEl && (!state.hasLicence || !state.providerConfigured) && !state.messages.length) {
        settingsPanelEl.hidden = false;
      }
      document.querySelectorAll('[data-auth-action]').forEach((button) => {
        button.hidden = Boolean(state.hasLicence);
      });
      if (historyStripEl) {
        const shouldShow = Boolean(state.hasRestorableChat) && historyVisible;
        historyStripEl.hidden = !shouldShow;
        historyStripEl.classList.toggle('visible', shouldShow);
      }
      if (toggleHistoryEl) {
        toggleHistoryEl.disabled = !state.hasRestorableChat;
      }
      if (historyCopyEl) {
        historyCopyEl.textContent = state.hasRestorableChat
          ? 'Previous chat available (' + state.restorableMessageCount + ' saved message' + (state.restorableMessageCount === 1 ? '' : 's') + ').'
          : '';
      }
      providerEl.innerHTML = '';
      if (!state.providers.length) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'No configured providers';
        option.selected = true;
        providerEl.appendChild(option);
        providerEl.disabled = true;
      } else {
        providerEl.disabled = false;
        for (const provider of state.providers) {
          const option = document.createElement('option');
          option.value = provider.id;
          option.textContent = provider.name;
          option.selected = provider.id === state.providerId;
          providerEl.appendChild(option);
        }
      }

      modelEl.innerHTML = '';
      for (const model of state.models) {
        const option = document.createElement('option');
        option.value = model;
        option.textContent = model;
        option.selected = model === state.model;
        modelEl.appendChild(option);
      }
      modelEl.disabled = !state.providers.length;

      messagesEl.innerHTML = '';
      if (!state.messages.length) {
        appendEmptyState(state);
        messagesEl.scrollTop = 0;
        return;
      }
      for (const [index, message] of state.messages.entries()) {
        const div = document.createElement('div');
        div.className = 'msg ' + message.role;
        if (message.role !== 'user' && message.kind) {
          const tag = document.createElement('div');
          tag.className = 'tag ' + message.kind;
          tag.textContent = message.kind === 'scan' ? 'Scan-backed' : 'Advisory';
          div.appendChild(tag);
        }
        const text = document.createElement('div');
        text.className = 'msg-body';
        text.textContent = message.content;
        div.appendChild(text);
        if (Array.isArray(message.actions) && message.actions.length) {
          const actions = document.createElement('div');
          actions.className = 'msg-actions';
          for (const action of message.actions) {
            const button = document.createElement('button');
            button.className = 'msg-action';
            button.textContent = action.label;
            button.addEventListener('click', () => {
              vscode.postMessage({ type: 'chat:messageAction', messageIndex: index, actionId: action.id });
            });
            actions.appendChild(button);
          }
          div.appendChild(actions);
        }
        messagesEl.appendChild(div);
      }
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    window.addEventListener('message', (event) => {
      const message = event.data;
      if (message.type === 'chat:state') {
        render(message);
      }
    });

    vscode.postMessage({ type: 'chat:ready' });

    function sendPrompt() {
      const prompt = promptEl.value.trim();
      if (!prompt) return;
      vscode.postMessage({ type: 'chat:send', prompt });
      promptEl.value = '';
      promptEl.focus();
    }

    document.getElementById('send').addEventListener('click', sendPrompt);
    newChatTopEl.addEventListener('click', () => {
      vscode.postMessage({ type: 'chat:clear' });
    });
    toggleSettingsTopEl.addEventListener('click', () => {
      settingsPanelEl.hidden = !settingsPanelEl.hidden;
    });
    closeSettingsEl.addEventListener('click', () => {
      settingsPanelEl.hidden = true;
    });
    toggleHistoryEl.addEventListener('click', () => {
      if (toggleHistoryEl.disabled) return;
      historyVisible = !historyVisible;
      historyStripEl.hidden = !historyVisible;
      historyStripEl.classList.toggle('visible', historyVisible);
    });
    restorePreviousEl.addEventListener('click', () => {
      vscode.postMessage({ type: 'chat:restorePrevious' });
      historyVisible = false;
      historyStripEl.hidden = true;
      historyStripEl.classList.remove('visible');
    });
    dismissHistoryEl.addEventListener('click', () => {
      historyVisible = false;
      historyStripEl.hidden = true;
      historyStripEl.classList.remove('visible');
    });
    providerEl.addEventListener('change', () => {
      vscode.postMessage({ type: 'chat:setProvider', providerId: providerEl.value });
    });
    modelEl.addEventListener('change', () => {
      vscode.postMessage({ type: 'chat:setModel', model: modelEl.value });
    });
    scanScopeBottomEl.addEventListener('change', () => {
      vscode.postMessage({ type: 'chat:setWorkingScope', scope: scanScopeBottomEl.value });
    });
    document.querySelectorAll('[data-action]').forEach((button) => {
      button.addEventListener('click', () => {
        postAction(button.getAttribute('data-action'));
        if (reportMenuEl && button.closest('#reportMenu')) {
          reportMenuEl.open = false;
        }
      });
    });
    runScanBottomEl.addEventListener('click', () => {
      vscode.postMessage({ type: 'chat:action', action: scanScopeBottomEl.value });
    });
    promptEl.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendPrompt();
      }
    });
  </script>
</body>
</html>`;
    }
}

export function parseChatIntent(prompt: string): ChatLocalIntent | undefined {
    const normalized = prompt.toLowerCase();
    const wantsScan = /\b(scan|audit|analy[sz]e|analy[sz]is|review)\b/.test(normalized);
    const wantsReport = /\b(report|summary|markdown|document)\b/.test(normalized);
    const wantsFolder = /\b(repo|repository|workspace|folder|project|codebase)\b/.test(normalized);
    const wantsFile = /\b(file|current file|this file|selected file)\b/.test(normalized);
    const wantsCalibration = /\b(calibration|score posture|risk posture|review scores|review scoring)\b/.test(normalized);
    const explicitFile = extractFileHint(prompt);

    if (wantsCalibration) {
        return { action: 'reviewRiskCalibration' };
    }

    if (wantsScan && wantsReport) {
        return { action: 'scanReport', fileHint: explicitFile };
    }

    if (wantsScan && (wantsFolder || /\bscan folder\b/.test(normalized))) {
        return { action: 'scanFolder' };
    }

    if (wantsScan && /\b(selected files|selected file|multiple files|many files|few files)\b/.test(normalized)) {
        return { action: 'scanSelectedFiles' };
    }

    if (wantsScan && /\b(open editors|open files|opened files|open tabs|current tabs)\b/.test(normalized)) {
        return { action: 'scanOpenEditors' };
    }

    if (wantsScan && (wantsFile || Boolean(explicitFile))) {
        return { action: 'scanFile', fileHint: explicitFile };
    }

    return undefined;
}

function extractFileHint(prompt: string): string | undefined {
    const explicitPath = prompt.match(/[A-Za-z0-9_\-./\\]+?\.(ts|tsx|js|jsx|py|java|cs|go|rs|php|rb|cpp|c|h)\b/i);
    if (explicitPath?.[0]) {
        return explicitPath[0];
    }

    const namedFile = prompt.match(/\b(?:scan|audit|review|analy[sz]e)(?:\s+(?:the|this|that|file|named))?\s+([A-Za-z0-9_\-. ]{3,80})/i);
    if (!namedFile?.[1]) {
        return undefined;
    }

    const cleaned = namedFile[1]
        .replace(/\b(?:and|with|using|please|for)\b.*$/i, '')
        .trim();

    if (!cleaned) {
        return undefined;
    }

    const genericTerms = new Set([
        'file',
        'this file',
        'current file',
        'selected file',
        'repo',
        'repository',
        'workspace',
        'folder',
        'project',
        'codebase',
    ]);

    return genericTerms.has(cleaned.toLowerCase()) ? undefined : cleaned;
}

function scoreFileMatch(fileHint: string, uri: vscode.Uri): number {
    const normalizedHint = normalizeToken(stripKnownExtension(path.basename(fileHint)) || fileHint);
    if (!normalizedHint) return 0;

    const basename = path.basename(uri.fsPath);
    const basenameNoExt = stripKnownExtension(basename);
    const relativePath = vscode.workspace.asRelativePath(uri, false);
    const normalizedBase = normalizeToken(basenameNoExt);
    const normalizedPath = normalizeToken(relativePath);

    if (normalizedBase === normalizedHint) return 100;
    if (normalizedPath.endsWith(normalizedHint)) return 95;
    if (normalizedBase.includes(normalizedHint) || normalizedHint.includes(normalizedBase)) return 90;
    if (normalizedPath.includes(normalizedHint)) return 80;

    const distance = levenshteinDistance(normalizedBase, normalizedHint);
    const maxLength = Math.max(normalizedBase.length, normalizedHint.length);
    if (maxLength > 0 && distance <= 2) {
        return 70 - distance;
    }

    return 0;
}

function stripKnownExtension(value: string): string {
    return value.replace(/\.(ts|tsx|js|jsx|py|java|cs|go|rs|php|rb|cpp|c|h)$/i, '');
}

function normalizeToken(value: string): string {
    return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function levenshteinDistance(left: string, right: string): number {
    const rows = left.length + 1;
    const cols = right.length + 1;
    const matrix = Array.from({ length: rows }, () => Array<number>(cols).fill(0));

    for (let row = 0; row < rows; row++) matrix[row][0] = row;
    for (let col = 0; col < cols; col++) matrix[0][col] = col;

    for (let row = 1; row < rows; row++) {
        for (let col = 1; col < cols; col++) {
            const substitutionCost = left[row - 1] === right[col - 1] ? 0 : 1;
            matrix[row][col] = Math.min(
                matrix[row - 1][col] + 1,
                matrix[row][col - 1] + 1,
                matrix[row - 1][col - 1] + substitutionCost,
            );
        }
    }

    return matrix[rows - 1][cols - 1];
}

function getNonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let value = '';
    for (let i = 0; i < 32; i++) {
        value += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return value;
}



