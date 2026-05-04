import * as vscode from 'vscode';
import * as path from 'path';
import { createHash } from 'crypto';
import { buildLicenceStatusSummary, buildPlanNextStepGuidance, buildPlanUpgradeMessage, buildScanLimitMessage, canRunScan, hasAiAssistantAccess, hasComparisonAccess, hasPromptEditorAccess, LicenceInfo, LicenceManager } from './licence/licenceManager';
import { getProviderApiKeySecretName, ProviderRegistry, persistProviderConnectionSetting, persistProviderSetting } from './providers/registry';
import { ProviderDisagreementProof, ScanEngine, ScanResult } from './scanner/scanEngine';
import { DiagnosticsProvider } from './diagnostics/diagnosticsProvider';
import { StatusBar } from './ui/statusBar';
import { SidebarProvider } from './panels/sidebarProvider';
import { ChatViewProvider } from './panels/chatViewProvider';
import { OWLVEX_PREVIEW_SCHEME, PreviewDocumentProvider } from './panels/previewDocumentProvider';
import { buildRiskCalibrationReport, StoredScanRecord } from './scanner/calibrationReview';
import { collectChangedScannableFiles, pickScanFile, pickScanFiles, resolveScanFileTarget, scanFolder, scanSelectedFiles } from './scanner/workspaceScanner';
import { generateReportFromSnapshot, ReportSnapshot, ReportVariant } from './scanner/reportGenerator';
import { FRAMEWORK_CATALOG, formatFrameworkSummary } from './frameworks/catalog';
import { configureFrameworkPackRuntime } from './frameworks/frameworkGrounding';
import { configureRulePackRuntime } from './frameworks/rulePackRegistry';
import { PROFILE } from './profile';
import { loadProjectContextInfo, promptForProjectRootSelection, resolveProjectRootInfo } from './projectContext';
import { applyRepoAiReviewSupport, buildRepoAiReviewPrompt, extractRepoAiSnippet, parseRepoAiReviewResponse, selectRepoAiCandidateRefs, summarizeRepoAiResults } from './repoAiReview';
import { initializeSecretStorage } from './secrets';
import { PackArtifactResponse, PackEntitlement, PackManifestEntry, RulePackClient } from './packs/packClient';
import { RulePackRuntimeContext } from './packs/packRuntime';

export let secrets: vscode.SecretStorage;

const MAX_STORED_SCANS = 20;
const MAX_STORED_REPORTS = 20;
const scanStore = new Map<string, StoredScanRecord>();
const reportStore = new Map<string, StoredReportRecord>();
const SCAN_STORE_KEY = `${PROFILE.storagePrefix}.scanStore`;
const REPORT_STORE_KEY = `${PROFILE.storagePrefix}.reportStore`;
const LAST_REPORT_SNAPSHOT_KEY = `${PROFILE.storagePrefix}.lastReportSnapshot`;
const RECENT_SCAN_SNAPSHOTS_KEY = `${PROFILE.storagePrefix}.recentScanSnapshots`;
const ISSUE_PACK_ID = 'owlvex.issue-pack.v1';
const ISSUE_MAPPING_PACK_ID = 'owlvex.issue-mapping-pack.v1';
const REMEDIATION_PACK_ID = 'owlvex.remediation-pack.v1';
const FRAMEWORK_PACK_ID = 'owlvex.framework-pack.2026.1';
const REPORT_ROOT_MARKERS = ['package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'pom.xml'];
const SOURCE_DIRECTORY_NAMES = new Set(['src', 'lib', 'routes', 'store', 'middleware', 'policies', 'controllers', 'services']);

interface ScanFileCommandResult {
    status: 'completed' | 'cancelled';
    uri?: vscode.Uri;
    result?: ScanResult;
}

interface ScanWorkspaceCommandResult {
    status: 'completed' | 'cancelled' | 'empty' | 'failed';
    root?: vscode.Uri;
    completed: number;
    totalFindings: number;
    errors: string[];
    results: Array<{ uri: vscode.Uri; result: ScanResult }>;
}

interface ScanSelectedFilesCommandResult {
    status: 'completed' | 'cancelled' | 'empty' | 'failed';
    files?: vscode.Uri[];
    completed: number;
    totalFindings: number;
    errors: string[];
    results: Array<{ uri: vscode.Uri; result: ScanResult }>;
}

interface ScanChangedFilesCommandResult {
    status: 'completed' | 'cancelled' | 'empty' | 'failed';
    root?: vscode.Uri;
    files?: vscode.Uri[];
    completed: number;
    totalFindings: number;
    errors: string[];
    results: Array<{ uri: vscode.Uri; result: ScanResult }>;
}

interface ScanOpenEditorsCommandResult {
    status: 'completed' | 'cancelled' | 'empty' | 'failed';
    files?: vscode.Uri[];
    completed: number;
    totalFindings: number;
    errors: string[];
    results: Array<{ uri: vscode.Uri; result: ScanResult }>;
}

interface ReportCommandResult {
    status: 'completed' | 'cancelled' | 'empty' | 'failed';
    reportUri?: vscode.Uri;
    averageScore?: number;
    providers?: string;
    models?: string;
    reportVariant?: ReportVariant;
    summary?: {
        completed: number;
        totalFindings: number;
        errors: string[];
        results: Array<{ uri: vscode.Uri; result: ScanResult }>;
    };
}

interface RecentScanSnapshot {
    provider: string;
    model: string;
    findingCount: number;
    score: number;
}

interface ReportCommandOptions {
    reportVariant?: ReportVariant;
}

async function uriExists(uri: vscode.Uri): Promise<boolean> {
    try {
        await vscode.workspace.fs.stat(uri);
        return true;
    } catch {
        return false;
    }
}

function isSourceSubdirectory(root: vscode.Uri): boolean {
    const parts = root.fsPath.split(/[\\/]/).map(part => part.toLowerCase());
    return parts.some(part => SOURCE_DIRECTORY_NAMES.has(part));
}

export async function resolveReportOutputRoot(outputRoot: vscode.Uri, results: Array<{ uri: vscode.Uri }>): Promise<{
    root: vscode.Uri;
    warning?: string;
}> {
    const firstResult = results[0]?.uri;
    const workspaceFolder = firstResult
        ? vscode.workspace.getWorkspaceFolder(firstResult)
        : vscode.workspace.workspaceFolders?.[0];
    const workspaceRoot = workspaceFolder?.uri.fsPath;
    const startPath = outputRoot.scheme === 'file'
        ? outputRoot.fsPath
        : firstResult
            ? path.dirname(firstResult.fsPath)
            : workspaceRoot;

    if (!startPath) {
        return { root: outputRoot };
    }

    let current = startPath;
    while (!workspaceRoot || current.toLowerCase().startsWith(workspaceRoot.toLowerCase())) {
        for (const marker of REPORT_ROOT_MARKERS) {
            if (await uriExists(vscode.Uri.file(path.join(current, marker)))) {
                return {
                    root: vscode.Uri.file(current),
                    warning: outputRoot.scheme !== 'file'
                        ? 'Report output root was invalid, so Owlvex used the nearest project root.'
                        : isSourceSubdirectory(outputRoot) && path.normalize(outputRoot.fsPath) !== path.normalize(current)
                            ? 'Report output was moved to the nearest project root so generated reports do not pollute source folders.'
                            : undefined,
                };
            }
        }

        const parent = path.dirname(current);
        if (parent === current) {
            break;
        }
        current = parent;
    }

    if (outputRoot.scheme === 'file' && !isSourceSubdirectory(outputRoot)) {
        return { root: outputRoot };
    }

    if (workspaceFolder) {
        return {
            root: workspaceFolder.uri,
            warning: outputRoot.scheme !== 'file'
                ? 'Report output root was invalid, so Owlvex used the workspace root.'
                : 'Report output was moved to the workspace root so generated reports do not pollute source folders.',
        };
    }

    return { root: outputRoot };
}

interface StoredReportRecord {
    reportId: string;
    reportUri: string;
    reportFileName: string;
    targetLabel: string;
    createdAt: string;
    fileCount: number;
    totalFindings: number;
    averageScore: number;
    providers: string[];
    models: string[];
    results: Array<{ uri: string; result: ScanResult }>;
}

export function getReportComparisonAnchorScanId(record: StoredReportRecord): string | undefined {
    for (const entry of record.results ?? []) {
        const scanId = String(entry?.result?.scanId ?? '').trim();
        if (scanId) {
            return scanId;
        }
    }

    return undefined;
}

function storeScanResult(scanId: string, result: ScanResult, targetLabel?: string): void {
    if (scanStore.size >= MAX_STORED_SCANS) {
        const firstKey = scanStore.keys().next().value;
        if (firstKey) scanStore.delete(firstKey);
    }
    scanStore.set(scanId, normalizeStoredScanRecord({
        scanId,
        result,
        targetLabel,
        scannedAt: new Date().toISOString(),
    }));
}

function serializeScanStore(): StoredScanRecord[] {
    return Array.from(scanStore.values()).map(item => ({
        ...item,
        result: normalizeScanResult(item.result),
    }));
}

function storeReportResult(record: StoredReportRecord): void {
    if (reportStore.size >= MAX_STORED_REPORTS) {
        const firstKey = reportStore.keys().next().value;
        if (firstKey) reportStore.delete(firstKey);
    }
    reportStore.set(record.reportId, normalizeStoredReportRecord(record));
}

function serializeReportStore(): StoredReportRecord[] {
    return Array.from(reportStore.values()).map(item => normalizeStoredReportRecord(item));
}

function normalizeScanResult(result: ScanResult): ScanResult {
    return {
        ...result,
        warnings: result.warnings ?? [],
        aiUsage: result.aiUsage ?? { requestCount: 0, totalTokens: 0 },
    };
}

function normalizeStoredReportRecord(item: StoredReportRecord): StoredReportRecord {
    return {
        ...item,
        providers: item.providers ?? [],
        models: item.models ?? [],
        results: (item.results ?? []).map(entry => ({
            uri: entry.uri,
            result: normalizeScanResult(entry.result),
        })),
    };
}

type UsageEventName =
    | 'scan_run'
    | 'scan_started'
    | 'scan_completed'
    | 'scan_failed'
    | 'finding_viewed'
    | 'fix_viewed'
    | 'second_scan'
    | 'session_return'
    | 'limit_hit'
    | 'feedback_positive'
    | 'feedback_negative'
    | 'registration_verified'
    | 'project_root_selected'
    | 'llm_provider_selected'
    | 'llm_model_selected'
    | 'llm_connection_configured'
    | 'fix_preview_generated'
    | 'fix_preview_started'
    | 'fix_preview_completed'
    | 'fix_preview_failed'
    | 'fix_preview_applied'
    | 'fix_preview_discarded'
    | 'fix_verification_completed'
    | 'report_created'
    | 'report_failed'
    | 'fix_applied'
    | 'fix_discarded'
    | 'post_fix_scan_completed';

interface UsageEventOptions {
    registry?: ProviderRegistry;
    includeProviderModel?: boolean;
    includeProject?: boolean;
}

type ScanLifecycleScope = 'current_file' | 'selected_files' | 'changed_files' | 'open_editors' | 'workspace';

const DEV_OBSERVABILITY_USAGE_EVENTS = new Set<UsageEventName>([
    'scan_started',
    'scan_completed',
    'scan_failed',
    'fix_preview_started',
    'fix_preview_completed',
    'fix_preview_failed',
    'report_created',
    'report_failed',
    'fix_applied',
    'fix_discarded',
    'post_fix_scan_completed',
]);

const MAX_REPO_AI_REVIEW_CANDIDATES = 3;
const PENDING_REGISTRATION_KEY = `${PROFILE.storagePrefix}.pendingRegistration`;

interface RegisterAccessResponse {
    status: 'verification_required';
    plan: 'free' | 'trial';
    email: string;
    delivery: 'email' | 'development_inline';
    expires_in_minutes: number;
    verification_code?: string;
}

interface RegisterTrackedAccessPayload {
    email: string;
    plan: 'free' | 'trial';
    name?: string;
    company?: string;
}

interface PendingRegistrationState extends RegisterAccessResponse {
    updated_at: string;
}

interface VerifyRegistrationResponse {
    customer_id: string;
    licence_id: string;
    licence_key: string;
    plan: string;
    team_name: string;
    email: string;
    expires_at: string | null;
}

interface UpdateTelemetryResponse {
    ok: boolean;
    licence_id: string;
    plan: string;
    telemetry_enabled: boolean;
    telemetry_required: boolean;
}

export interface OnboardingActionChoice {
    label: string;
    command: string;
    args?: unknown[];
}

function formatStoredScanTimestamp(value?: string): string {
    if (!value) {
        return 'time unknown';
    }

    const timestamp = new Date(value);
    if (Number.isNaN(timestamp.getTime())) {
        return value;
    }

    return timestamp.toISOString().replace('T', ' ').replace('.000Z', ' UTC').replace('Z', ' UTC');
}

function shortenScanId(scanId: string): string {
    return String(scanId ?? '').slice(0, 8) || 'unknown';
}

export function buildStoredScanComparisonChoice(record: StoredScanRecord): {
    label: string;
    description: string;
    detail: string;
    record: StoredScanRecord;
} {
    const target = record.targetLabel?.trim() || `Scan ${shortenScanId(record.scanId)}`;
    const result = record.result;
    const providerModel = [result.provider, result.model].filter(Boolean).join(' / ') || 'provider/model unknown';

    return {
        label: target,
        description: `${formatStoredScanTimestamp(record.scannedAt)} | ${providerModel}`,
        detail: `${result.score.toFixed(1)}/10 | ${result.findings.length} finding(s) | scan ${shortenScanId(record.scanId)}`,
        record,
    };
}

export function buildStoredReportComparisonChoice(record: StoredReportRecord): {
    label: string;
    description: string;
    detail: string;
    record: StoredReportRecord;
} {
    const providerModel = [record.providers.join(', '), record.models.join(', ')].filter(Boolean).join(' / ') || 'provider/model unknown';
    return {
        label: record.targetLabel?.trim() || record.reportFileName,
        description: `${formatStoredScanTimestamp(record.createdAt)} | ${providerModel}`,
        detail: `${record.fileCount} file(s) | ${record.totalFindings} finding(s) | avg ${record.averageScore.toFixed(1)}/10 | ${record.reportFileName}`,
        record,
    };
}

export function selectLatestTwoReports(records: StoredReportRecord[]): {
    baseline: StoredReportRecord;
    current: StoredReportRecord;
} | undefined {
    if (records.length < 2) {
        return undefined;
    }

    const sorted = [...records].sort((left, right) => {
        const leftTime = new Date(left.createdAt).getTime();
        const rightTime = new Date(right.createdAt).getTime();
        return rightTime - leftTime;
    });

    return {
        baseline: sorted[1],
        current: sorted[0],
    };
}

export function orderReportsForComparison(reportA: StoredReportRecord, reportB: StoredReportRecord): {
    baseline: StoredReportRecord;
    current: StoredReportRecord;
    wasReordered: boolean;
} {
    const timeA = new Date(reportA.createdAt).getTime();
    const timeB = new Date(reportB.createdAt).getTime();
    const validA = Number.isFinite(timeA);
    const validB = Number.isFinite(timeB);

    if (validA && validB && timeA > timeB) {
        return {
            baseline: reportB,
            current: reportA,
            wasReordered: true,
        };
    }

    return {
        baseline: reportA,
        current: reportB,
        wasReordered: false,
    };
}

function normalizeStoredScanRecord(item: { scanId: string; result: ScanResult; targetLabel?: string; scannedAt?: string }): StoredScanRecord {
    return {
        scanId: item.scanId,
        result: normalizeScanResult(item.result),
        targetLabel: item.targetLabel,
        scannedAt: item.scannedAt,
    };
}

function collectOpenEditorUris(): vscode.Uri[] {
    const seen = new Map<string, vscode.Uri>();
    for (const document of vscode.workspace.textDocuments) {
        if (document.uri.scheme !== 'file') {
            continue;
        }

        const ext = path.extname(document.uri.fsPath).toLowerCase();
        if (!['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.cs', '.go', '.rs', '.php', '.rb', '.cpp', '.c', '.h'].includes(ext)) {
            continue;
        }

        seen.set(document.uri.fsPath, document.uri);
    }

    return [...seen.values()];
}

const DEFAULT_PROJECT_CONTEXT_RELATIVE_PATH = '.owlvex/project-context.md';
const DEFAULT_DESIGN_CONTEXT_RELATIVE_DIR = '.owlvex/design';
const DEFAULT_DRIFT_BOX_RELATIVE_DIR = '.owlvex/drift';
const DESIGN_CONTEXT_FILE_SETTING = 'designContextFile';
const DRIFT_BOX_FILE_SETTING = 'driftBoxFile';
const DRIFT_SCRIPTS_ROOT_SETTING = 'driftScriptsRoot';

function buildDefaultProjectContextContent(): string {
    return [
        '# Owlvex Project Context Contract',
        '',
        'Use this file to help Owlvex understand the project.',
        '',
        'Include only the context that materially improves scanning or remediation, such as:',
        '',
        '- product purpose',
        '- important user roles',
        '- auth and tenant model',
        '- sensitive data handled here',
        '- critical workflows',
        '- architectural trust boundaries',
        '- required security invariants',
        '- generated code or folders that should be treated specially',
        '',
        'Examples:',
        '',
        '- All document reads must be tenant-scoped.',
        '- Admin actions must pass through policy middleware.',
        '- JWT verification happens only in auth middleware.',
        '- The exports folder contains generated code and should not drive primary findings.',
    ].join('\n');
}

async function openOrCreateProjectContext(): Promise<{ uri: vscode.Uri; created: boolean; relativePath?: string }> {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const configuredFile = config.get<string>('projectContextFile', '').trim();
    const projectRoot = await resolveProjectRootInfo();

    if (!projectRoot.uri) {
        const document = await vscode.workspace.openTextDocument({
            language: 'markdown',
            content: buildDefaultProjectContextContent(),
        });
        await vscode.window.showTextDocument(document, { preview: false });
        return { uri: document.uri, created: true };
    }

    const relativePath = configuredFile || DEFAULT_PROJECT_CONTEXT_RELATIVE_PATH;
    const targetFsPath = path.isAbsolute(relativePath)
        ? relativePath
        : path.join(projectRoot.uri.fsPath, relativePath);
    const targetUri = vscode.Uri.file(targetFsPath);

    let created = false;
    try {
        await vscode.workspace.fs.stat(targetUri);
    } catch {
        await vscode.workspace.fs.createDirectory(vscode.Uri.file(path.dirname(targetFsPath)));
        await vscode.workspace.fs.writeFile(targetUri, Buffer.from(buildDefaultProjectContextContent(), 'utf8'));
        created = true;
    }

    const normalizedRelative = vscode.workspace.asRelativePath(targetUri, false);
    if (!configuredFile || configuredFile !== normalizedRelative) {
        await persistProviderSetting('projectContextFile', normalizedRelative);
    }

    const document = await vscode.workspace.openTextDocument(targetUri);
    await vscode.window.showTextDocument(document, { preview: false });
    return { uri: targetUri, created, relativePath: normalizedRelative };
}

function getFrameworkConfigurationTarget(): vscode.ConfigurationTarget {
    return vscode.workspace.workspaceFolders?.length
        ? vscode.ConfigurationTarget.Workspace
        : vscode.ConfigurationTarget.Global;
}

function normalizeServiceUrl(value: string): string {
    return value.trim().replace(/\/+$/, '');
}

function isLikelyAzureFoundryEndpoint(value: string): boolean {
    const normalized = normalizeServiceUrl(value);
    return /^https:\/\/[A-Za-z0-9-]+\.(openai\.azure\.com|services\.ai\.azure\.com)$/i.test(normalized);
}

function getProviderSetupSummary(providerId: string): string {
    switch (providerId) {
        case 'azure-foundry':
            return 'Paste the Azure endpoint, the deployment name you created in Azure AI Foundry, and the API key from Keys and Endpoint.';
        case 'custom':
            return 'Provide the base URL, the exact model name, and an API key if your endpoint requires one.';
        case 'ollama':
            return 'Provide the Ollama host URL and the local model name installed on that host.';
        case 'anthropic':
            return 'Provide the API key and the exact Claude model name you want Owlvex to use.';
        default:
            return 'Provide the API key and, when applicable, the exact model name you want Owlvex to use.';
    }
}

async function testCurrentProviderConnection(registry: ProviderRegistry): Promise<{ success: boolean; latencyMs: number; message?: string; providerName: string; model: string }> {
    const provider = registry.getActive();
    const result = await provider.testConnection();
    return {
        ...result,
        providerName: provider.name,
        model: provider.selectedModel,
    };
}

async function testBackendConnection(apiUrl: string): Promise<{ success: boolean; latencyMs: number; message?: string }> {
    const start = Date.now();
    try {
        const res = await fetch(`${apiUrl}/health`);
        if (!res.ok) {
            return {
                success: false,
                latencyMs: Date.now() - start,
                message: `Backend health check failed (HTTP ${res.status})`,
            };
        }

        return {
            success: true,
            latencyMs: Date.now() - start,
        };
    } catch (error: any) {
        return {
            success: false,
            latencyMs: Date.now() - start,
            message: error?.message || 'Backend health check failed.',
        };
    }
}

async function trackUsageEvent(
    licenceMgr: LicenceManager,
    getApiUrl: () => string,
    eventName: UsageEventName,
    metadata: Record<string, unknown> = {},
    options: UsageEventOptions = {},
): Promise<void> {
    try {
        const licenceKey = await licenceMgr.getKey();
        if (!licenceKey) {
            return;
        }
        const cachedInfo = licenceMgr.getCachedInfo();
        if (cachedInfo && !cachedInfo.features.telemetryEnabled) {
            return;
        }

        const enrichedMetadata: Record<string, unknown> = {
            ...metadata,
        };

        if (options.includeProviderModel && options.registry) {
            const provider = options.registry.getActive();
            enrichedMetadata.provider ??= provider.id;
            enrichedMetadata.model ??= provider.selectedModel;
        }

        if (options.includeProject) {
            const projectMetadata = await buildProjectUsageMetadata();
            for (const [key, value] of Object.entries(projectMetadata)) {
                if (enrichedMetadata[key] === undefined) {
                    enrichedMetadata[key] = value;
                }
            }
        }

        const response = await fetch(`${getApiUrl()}/v1/usage/events`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Licence-Key': licenceKey,
            },
            body: JSON.stringify({
                event_name: eventName,
                metadata: compactUsageMetadata(enrichedMetadata),
            }),
        });

        if (!response.ok) {
            console.debug(`${PROFILE.displayLabel}: usage event ${eventName} failed with HTTP ${response.status}`);
        }
    } catch (error) {
        console.debug(`${PROFILE.displayLabel}: usage event ${eventName} failed`, error);
    }
}

function buildDefaultDesignSystemContent(): string {
    return [
        '# Owlvex Design Context',
        '',
        'Use this folder to describe what the system is intended to do so Owlvex can ground AI-assisted review in project intent.',
        '',
        'Recommended sections:',
        '',
        '- product purpose',
        '- important actors and roles',
        '- sensitive assets and data',
        '- trust boundaries',
        '- critical workflows',
        '- data ownership rules',
        '- authorization model',
        '',
        'Design context is especially useful when STRIDE is selected because STRIDE depends on assets, actors, boundaries, and intended flows.',
    ].join('\n');
}

function buildDefaultStrideNotesContent(): string {
    return [
        '# STRIDE Notes',
        '',
        'Use this file to capture STRIDE-specific assumptions for Owlvex.',
        '',
        '## Spoofing',
        '',
        '- Which identities can act in the system?',
        '- Where are authentication boundaries?',
        '',
        '## Tampering',
        '',
        '- Which requests mutate state?',
        '- Which inputs must be signed, validated, or policy checked?',
        '',
        '## Repudiation',
        '',
        '- Which actions require audit trails?',
        '',
        '## Information Disclosure',
        '',
        '- Which data must be tenant, customer, or role scoped?',
        '',
        '## Denial Of Service',
        '',
        '- Which workflows are resource-sensitive?',
        '',
        '## Elevation Of Privilege',
        '',
        '- Which role or permission changes require stronger controls?',
    ].join('\n');
}

function buildDefaultDriftConfigContent(): string {
    return JSON.stringify({
        version: 1,
        checks: [
            {
                id: 'example-contract-check',
                label: 'Example contract check',
                command: 'node .owlvex/drift/scripts/example-contract-check.mjs',
                frameworks: ['STRIDE', 'OWASP'],
                scope: ['scan', 'post-fix'],
                timeoutSeconds: 30,
                enabled: false,
            },
        ],
    }, null, 2);
}

function buildDefaultDriftInvariantsContent(): string {
    return [
        '# Owlvex Drift Invariants',
        '',
        'Use this file to document behavior that must not drift during AI-assisted fixes.',
        'Drift checks are report-only signals. They should produce clear pass/fail output, but they do not block scan completion, fix application, or security-clean status.',
        '',
        'Examples:',
        '',
        '- Login must still reject disabled users.',
        '- Tenant-scoped reads must not return another tenant\'s data.',
        '- Refund approval must still write an audit record.',
        '- Import routes must preserve the documented payload shape.',
    ].join('\n');
}

function buildDefaultDriftScriptContent(): string {
    return [
        "console.log('Example Owlvex drift check is disabled by default.');",
        "console.log('Replace this script with a repo-owned check and set enabled=true in owlvex-drift.json.');",
        'process.exit(0);',
    ].join('\n');
}

async function writeFileIfMissing(uri: vscode.Uri, content: string): Promise<boolean> {
    try {
        await vscode.workspace.fs.stat(uri);
        return false;
    } catch {
        await vscode.workspace.fs.createDirectory(vscode.Uri.file(path.dirname(uri.fsPath)));
        await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
        return true;
    }
}

function resolveUserConfiguredPath(value: string, projectRoot: vscode.Uri): string {
    return path.isAbsolute(value) ? value : path.join(projectRoot.fsPath, value);
}

async function persistWorkspaceSetting(key: string, value: string): Promise<void> {
    await vscode.workspace.getConfiguration(PROFILE.configSection).update(
        key,
        value,
        vscode.workspace.workspaceFolders?.length ? vscode.ConfigurationTarget.Workspace : vscode.ConfigurationTarget.Global,
    );
}

async function openOrCreateDesignContext(): Promise<{ uri: vscode.Uri; created: boolean; relativePath?: string }> {
    const projectRoot = await resolveProjectRootInfo();
    if (!projectRoot.uri) {
        const document = await vscode.workspace.openTextDocument({
            language: 'markdown',
            content: buildDefaultDesignSystemContent(),
        });
        await vscode.window.showTextDocument(document, { preview: false });
        return { uri: document.uri, created: true };
    }

    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    let configuredFile = config.get<string>(DESIGN_CONTEXT_FILE_SETTING, '').trim();
    if (!configuredFile) {
        const selected = await vscode.window.showOpenDialog({
            canSelectFiles: true,
            canSelectFolders: false,
            canSelectMany: false,
            title: 'Select Owlvex Design Box file',
            openLabel: 'Use As Design Box',
            defaultUri: vscode.Uri.file(path.join(projectRoot.uri.fsPath, DEFAULT_DESIGN_CONTEXT_RELATIVE_DIR)),
            filters: { 'Design context': ['md', 'txt', 'docx', 'pdf'] },
        });
        if (selected?.[0]) {
            configuredFile = vscode.workspace.asRelativePath(selected[0], false);
            await persistWorkspaceSetting(DESIGN_CONTEXT_FILE_SETTING, configuredFile);
        }
    }

    const designDir = path.join(projectRoot.uri.fsPath, DEFAULT_DESIGN_CONTEXT_RELATIVE_DIR);
    const systemUri = vscode.Uri.file(configuredFile
        ? resolveUserConfiguredPath(configuredFile, projectRoot.uri)
        : path.join(designDir, 'system.md'));
    const strideUri = vscode.Uri.file(path.join(designDir, 'stride-notes.md'));
    const created = await writeFileIfMissing(systemUri, buildDefaultDesignSystemContent());
    if (!configuredFile) {
        await persistWorkspaceSetting(DESIGN_CONTEXT_FILE_SETTING, vscode.workspace.asRelativePath(systemUri, false));
        await writeFileIfMissing(strideUri, buildDefaultStrideNotesContent());
    }

    const document = await vscode.workspace.openTextDocument(systemUri);
    await vscode.window.showTextDocument(document, { preview: false });
    return { uri: systemUri, created, relativePath: vscode.workspace.asRelativePath(systemUri, false) };
}

async function openOrCreateDriftBox(): Promise<{ uri: vscode.Uri; created: boolean; relativePath?: string }> {
    const projectRoot = await resolveProjectRootInfo();
    if (!projectRoot.uri) {
        const document = await vscode.workspace.openTextDocument({
            language: 'json',
            content: buildDefaultDriftConfigContent(),
        });
        await vscode.window.showTextDocument(document, { preview: false });
        return { uri: document.uri, created: true };
    }

    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    let configuredFile = config.get<string>(DRIFT_BOX_FILE_SETTING, '').trim();
    let configuredScriptsRoot = config.get<string>(DRIFT_SCRIPTS_ROOT_SETTING, '').trim();
    if (!configuredFile) {
        const selected = await vscode.window.showOpenDialog({
            canSelectFiles: true,
            canSelectFolders: false,
            canSelectMany: false,
            title: 'Select Owlvex Drift Box config',
            openLabel: 'Use As Drift Box',
            defaultUri: vscode.Uri.file(path.join(projectRoot.uri.fsPath, DEFAULT_DRIFT_BOX_RELATIVE_DIR)),
            filters: { 'Drift config': ['json'] },
        });
        if (selected?.[0]) {
            configuredFile = vscode.workspace.asRelativePath(selected[0], false);
            await persistWorkspaceSetting(DRIFT_BOX_FILE_SETTING, configuredFile);
        }
    }

    if (configuredFile && !configuredScriptsRoot) {
        const configDir = path.dirname(resolveUserConfiguredPath(configuredFile, projectRoot.uri));
        const selectedScripts = await vscode.window.showOpenDialog({
            canSelectFiles: false,
            canSelectFolders: true,
            canSelectMany: false,
            title: 'Select Owlvex Drift scripts folder',
            openLabel: 'Use As Drift Scripts Folder',
            defaultUri: vscode.Uri.file(path.join(configDir, 'scripts')),
        });
        const scriptsUri = selectedScripts?.[0] ?? vscode.Uri.file(path.join(configDir, 'scripts'));
        configuredScriptsRoot = vscode.workspace.asRelativePath(scriptsUri, false);
        await persistWorkspaceSetting(DRIFT_SCRIPTS_ROOT_SETTING, configuredScriptsRoot);
    }

    const driftDir = path.join(projectRoot.uri.fsPath, DEFAULT_DRIFT_BOX_RELATIVE_DIR);
    const configUri = vscode.Uri.file(path.join(driftDir, 'owlvex-drift.json'));
    const targetConfigUri = vscode.Uri.file(configuredFile
        ? resolveUserConfiguredPath(configuredFile, projectRoot.uri)
        : configUri.fsPath);
    const scriptsRoot = configuredScriptsRoot
        ? resolveUserConfiguredPath(configuredScriptsRoot, projectRoot.uri)
        : path.join(path.dirname(targetConfigUri.fsPath), 'scripts');
    const invariantsUri = vscode.Uri.file(path.join(path.dirname(targetConfigUri.fsPath), 'invariants.md'));
    const scriptUri = vscode.Uri.file(path.join(scriptsRoot, 'example-contract-check.mjs'));
    const created = await writeFileIfMissing(targetConfigUri, buildDefaultDriftConfigContent());
    await persistWorkspaceSetting(DRIFT_BOX_FILE_SETTING, vscode.workspace.asRelativePath(targetConfigUri, false));
    await persistWorkspaceSetting(DRIFT_SCRIPTS_ROOT_SETTING, vscode.workspace.asRelativePath(vscode.Uri.file(scriptsRoot), false));
    await writeFileIfMissing(invariantsUri, buildDefaultDriftInvariantsContent());
    await writeFileIfMissing(scriptUri, buildDefaultDriftScriptContent());

    const document = await vscode.workspace.openTextDocument(targetConfigUri);
    await vscode.window.showTextDocument(document, { preview: false });
    return { uri: targetConfigUri, created, relativePath: vscode.workspace.asRelativePath(targetConfigUri, false) };
}

function isDevObservabilityTelemetryEnabled(info: LicenceInfo | null | undefined): boolean {
    return Boolean(info?.features.telemetryEnabled && info.features.telemetryProfile === 'dev_observability');
}

function classifyTelemetryError(error: any): string {
    const message = String(error?.message ?? error ?? '').toLowerCase();
    if (message.includes('timeout') || message.includes('timed out')) return 'timeout';
    if (message.includes('rate limit') || message.includes('429')) return 'rate_limit';
    if (message.includes('parse') || message.includes('json')) return 'parse';
    if (message.includes('validation') || message.includes('invalid')) return 'validation';
    if (message.includes('cancel')) return 'cancelled';
    if (message.includes('provider') || message.includes('model') || message.includes('api')) return 'provider_error';
    return 'unknown';
}

function emitDevScanLifecycleEvent(
    licenceMgr: LicenceManager,
    getApiUrl: () => string,
    registry: ProviderRegistry,
    eventName: Extract<UsageEventName, 'scan_started' | 'scan_completed' | 'scan_failed'>,
    metadata: {
        scope: ScanLifecycleScope;
        startedAt: number;
        fileCount?: number;
        findingCount?: number;
        status: 'started' | 'completed' | 'failed';
        stage?: string;
        errorKind?: string;
    },
): void {
    if (!isDevObservabilityTelemetryEnabled(licenceMgr.getCachedInfo())) {
        return;
    }

    void trackUsageEvent(licenceMgr, getApiUrl, eventName, {
        telemetry_profile: 'dev_observability',
        scope: metadata.scope,
        status: metadata.status,
        stage: metadata.stage,
        error_kind: metadata.errorKind,
        file_count: metadata.fileCount,
        finding_count: metadata.findingCount,
        duration_ms: Math.max(0, Date.now() - metadata.startedAt),
        agent_mode: 'finder',
        analysis_mix: 'deterministic+finder',
    }, {
        registry,
        includeProviderModel: true,
        includeProject: true,
    });
}

function emitDevWorkflowLifecycleEvent(
    licenceMgr: LicenceManager,
    getApiUrl: () => string,
    registry: ProviderRegistry,
    eventName: Extract<UsageEventName, 'report_created' | 'report_failed'>,
    metadata: Record<string, unknown>,
): void {
    if (!isDevObservabilityTelemetryEnabled(licenceMgr.getCachedInfo())) {
        return;
    }

    void trackUsageEvent(licenceMgr, getApiUrl, eventName, {
        telemetry_profile: 'dev_observability',
        ...metadata,
    }, {
        registry,
        includeProviderModel: true,
        includeProject: true,
    });
}

function buildFindingUsageMetadata(finding: any): Record<string, unknown> {
    return {
        rule_code: finding?.ruleCode ?? finding?.rule_code ?? null,
        canonical_id: finding?.canonicalId ?? finding?.issue_id ?? null,
        severity: finding?.severity ?? null,
        scan_tier: finding?.scanTier ?? finding?.scan_tier ?? null,
    };
}

async function promptForSetting(
    settingKey: string,
    prompt: string,
    placeHolder: string,
    validateInput?: (value: string) => string | undefined,
): Promise<string | undefined> {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const current = config.get<string>(settingKey, '');
    const value = await vscode.window.showInputBox({
        prompt,
        placeHolder,
        value: current,
        ignoreFocusOut: true,
        validateInput,
    });

    if (!value) {
        return undefined;
    }

    const normalized = settingKey.endsWith('endpoint') || settingKey.endsWith('baseUrl')
        ? normalizeServiceUrl(value)
        : value.trim();
    await persistProviderConnectionSetting(settingKey, normalized);
    return normalized;
}

async function migrateWorkspaceProviderSettingsToGlobalDefaults(): Promise<void> {
    if (!vscode.workspace.workspaceFolders?.length) {
        return;
    }

    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const connectionKeys = new Set<string>(['provider']);
    for (const providerId of ['azure-foundry', 'anthropic', 'openai', 'mistral', 'gemini', 'groq', 'ollama', 'custom']) {
        for (const key of getProviderConnectionSettingKeys(providerId)) {
            connectionKeys.add(key);
        }
    }

    for (const key of connectionKeys) {
        const inspected = config.inspect<unknown>(key);
        if (inspected?.workspaceValue === undefined || inspected.globalValue !== undefined) {
            continue;
        }

        await config.update(key, inspected.workspaceValue, vscode.ConfigurationTarget.Global);
    }
}

export function buildProviderThrottleOverrideSnippet(providerId: string): string {
    const defaults: Record<string, Record<string, number>> = {
        'azure-foundry': {
            maxConcurrent: 1,
            minSpacingMs: 7000,
            baseBackoffMs: 10000,
            maxBackoffMs: 60000,
            retryAttempts: 2,
        },
        openai: {
            maxConcurrent: 2,
            minSpacingMs: 250,
            baseBackoffMs: 2000,
            maxBackoffMs: 30000,
            retryAttempts: 2,
        },
        mistral: {
            maxConcurrent: 2,
            minSpacingMs: 250,
            baseBackoffMs: 2000,
            maxBackoffMs: 30000,
            retryAttempts: 2,
        },
        gemini: {
            maxConcurrent: 2,
            minSpacingMs: 250,
            baseBackoffMs: 2000,
            maxBackoffMs: 30000,
            retryAttempts: 2,
        },
        groq: {
            maxConcurrent: 3,
            minSpacingMs: 100,
            baseBackoffMs: 1500,
            maxBackoffMs: 15000,
            retryAttempts: 2,
        },
        custom: {
            maxConcurrent: 2,
            minSpacingMs: 250,
            baseBackoffMs: 2000,
            maxBackoffMs: 30000,
            retryAttempts: 2,
        },
        ollama: {
            maxConcurrent: 2,
            minSpacingMs: 250,
            baseBackoffMs: 2000,
            maxBackoffMs: 30000,
            retryAttempts: 2,
        },
    };

    const profile = defaults[providerId] ?? defaults.openai;
    return JSON.stringify({
        [providerId]: profile,
    }, null, 2);
}

export async function configureProviderThrottlingForActiveProvider(
    registryLike: { getActive(): { id: string; name: string } },
): Promise<void> {
    const provider = registryLike.getActive();
    const snippet = buildProviderThrottleOverrideSnippet(provider.id);
    await vscode.env.clipboard.writeText(snippet);
    await vscode.commands.executeCommand('workbench.action.openSettings', `${PROFILE.configSection}.providerThrottleOverrides`);
    vscode.window.showInformationMessage(
        `${PROFILE.displayLabel}: Opened provider throttling settings. A starter override for ${provider.name} was copied to the clipboard.`,
    );
}

function compactUsageMetadata(metadata: Record<string, unknown>): Record<string, unknown> {
    return Object.fromEntries(
        Object.entries(metadata).filter(([, value]) => value !== undefined),
    );
}

async function buildProjectUsageMetadata(): Promise<Record<string, unknown>> {
    const projectRoot = await resolveProjectRootInfo();
    const projectMode = projectRoot.uri
        ? (projectRoot.isConfigured ? 'configured' : 'workspace_default')
        : 'unset';

    return compactUsageMetadata({
        project_id: projectRoot.uri ? createHash('sha256').update(projectRoot.uri.fsPath.toLowerCase()).digest('hex').slice(0, 16) : undefined,
        project_mode: projectMode,
        project_configured: projectRoot.isConfigured,
    });
}

async function updateTelemetryPreferenceRequest(
    apiUrl: string,
    licenceKey: string,
    enabled: boolean,
): Promise<UpdateTelemetryResponse> {
    const response = await fetch(`${apiUrl}/v1/licences/telemetry`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Licence-Key': licenceKey,
        },
        body: JSON.stringify({ enabled }),
    });

    const body = await response.json().catch(() => ({})) as Record<string, any>;
    if (!response.ok) {
        throw new Error(String(body?.detail ?? `Telemetry update failed (HTTP ${response.status})`));
    }

    return body as UpdateTelemetryResponse;
}

async function resolveLicenceInfoForAccess(
    licenceMgr: LicenceManager,
    getApiUrl: () => string,
): Promise<LicenceInfo | null> {
    const cached = licenceMgr.getCachedInfo();
    if (cached) {
        return cached;
    }

    try {
        return await licenceMgr.validate(getApiUrl());
    } catch {
        return null;
    }
}

async function ensureScanAllowed(
    licenceMgr: LicenceManager,
    getApiUrl: () => string,
): Promise<LicenceInfo | null> {
    return resolveLicenceInfoForAccess(licenceMgr, getApiUrl);
}

export function shouldPromptUsefulnessFeedback(
    info: LicenceInfo | null | undefined,
    sessionScanCount: number,
    alreadyPrompted: boolean,
): boolean {
    if (alreadyPrompted || !info) {
        return false;
    }

    if (!['free', 'trial'].includes(info.plan)) {
        return false;
    }

    return sessionScanCount === 1;
}

export function buildUsefulnessPromptMessage(info: LicenceInfo | null | undefined): string {
    if (!info) {
        return 'Was this useful?';
    }

    if (info.plan === 'trial') {
        return 'Was this useful so far during your trial?';
    }

    return 'Was this useful?';
}

export function buildRegistrationSuccessMessage(
    plan: 'free' | 'trial',
    email: string,
    info: LicenceInfo | null | undefined,
): string {
    const heading = plan === 'trial'
        ? `Trial started for ${email}.`
        : `Free access registered for ${email}.`;
    const summary = info
        ? buildLicenceStatusSummary(info)
        : `Licence: ${plan.charAt(0).toUpperCase()}${plan.slice(1)}`;

    return `${heading}\n${summary}\n${buildPlanNextStepGuidance(info).join('\n')}`;
}

function buildBackendConnectionSummary(apiUrl: string): string {
    return normalizeServiceUrl(apiUrl) === normalizeServiceUrl(PROFILE.defaultApiUrl)
        ? `Owlvex is using this build's packaged backend: ${apiUrl}`
        : `Owlvex is using an explicit backend override: ${apiUrl}`;
}

export function buildVerificationPromptMessage(
    registration: RegisterAccessResponse,
): string {
    const lines = [
        registration.delivery === 'email'
            ? `A verification code was sent to ${registration.email}.`
            : `Development verification code generated for ${registration.email}.`,
        `Plan: ${registration.plan}`,
        `Expires in: ${registration.expires_in_minutes} minute(s)`,
    ];

    if (registration.verification_code) {
        lines.push(`Verification code: ${registration.verification_code}`);
    }

    lines.push('Enter the verification code to activate your licence.');
    lines.push('If the code expires or does not arrive, use Resend Code to issue a new one.');
    return lines.join('\n');
}

async function completeTrackedRegistrationVerification(
    apiUrl: string,
    initialRegistration: RegisterAccessResponse,
    onRegistrationUpdated?: (registration: RegisterAccessResponse) => Thenable<void> | Promise<void> | void,
): Promise<VerifyRegistrationResponse | undefined> {
    let registration = initialRegistration;

    while (true) {
        const code = await vscode.window.showInputBox({
            prompt: `Enter the verification code sent to ${registration.email}`,
            placeHolder: '123456',
            ignoreFocusOut: true,
            value: registration.verification_code ?? '',
        });

        if (!code?.trim()) {
            const choice = await vscode.window.showInformationMessage(
                `${PROFILE.displayLabel}: Registration is pending until you verify the email code.`,
                'Enter Code',
                'Resend Code',
            );

            if (choice === 'Resend Code') {
                registration = await registerTrackedAccessRequest(apiUrl, {
                    email: registration.email,
                    plan: registration.plan,
                });
                await onRegistrationUpdated?.(registration);
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: ${buildVerificationPromptMessage(registration)}`,
                );
                continue;
            }

            if (choice === 'Enter Code') {
                continue;
            }

            return undefined;
        }

        try {
            return await verifyTrackedAccessRequest(apiUrl, {
                email: registration.email,
                code: code.trim(),
            });
        } catch (error: any) {
            const choice = await vscode.window.showWarningMessage(
                `${PROFILE.displayLabel}: ${error.message}`,
                'Try Again',
                'Resend Code',
                'Cancel',
            );

            if (choice === 'Resend Code') {
                registration = await registerTrackedAccessRequest(apiUrl, {
                    email: registration.email,
                    plan: registration.plan,
                });
                await onRegistrationUpdated?.(registration);
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: ${buildVerificationPromptMessage(registration)}`,
                );
                continue;
            }

            if (choice === 'Try Again') {
                continue;
            }

            return undefined;
        }
    }
}

export function buildBackendConnectedNoLicenceChoices(): OnboardingActionChoice[] {
    return [
        {
            label: 'Use Free',
            command: PROFILE.commands.registerAccess,
            args: ['free'],
        },
        {
            label: 'Start Trial',
            command: PROFILE.commands.registerAccess,
            args: ['trial'],
        },
        {
            label: 'Enter Licence',
            command: PROFILE.commands.enterLicence,
        },
    ];
}

export function buildRegistrationCompletionChoices(): OnboardingActionChoice[] {
    return [
        {
            label: 'Configure LLM',
            command: PROFILE.commands.setupAI,
        },
        {
            label: 'Scan Workspace',
            command: PROFILE.commands.scanWorkspace,
        },
        {
            label: 'Scan Current File',
            command: PROFILE.commands.scanFile,
        },
    ];
}

export function buildBackendAndLicenceReadyChoices(): OnboardingActionChoice[] {
    return [
        {
            label: 'Configure LLM',
            command: PROFILE.commands.setupAI,
        },
        {
            label: 'Scan Current File',
            command: PROFILE.commands.scanFile,
        },
        {
            label: 'Scan Workspace',
            command: PROFILE.commands.scanWorkspace,
        },
    ];
}

export function buildProviderConnectedChoices(): OnboardingActionChoice[] {
    return [
        {
            label: 'Test Trial Setup',
            command: PROFILE.commands.testTrialSetup,
        },
    ];
}

async function promptOnboardingChoices(
    message: string,
    actions: OnboardingActionChoice[],
): Promise<void> {
    if (!actions.length) {
        vscode.window.showInformationMessage(message);
        return;
    }

    const choice = await vscode.window.showInformationMessage(
        message,
        ...actions.map(action => action.label),
    );
    const selected = actions.find(action => action.label === choice);
    if (!selected) {
        return;
    }

    await vscode.commands.executeCommand(selected.command, ...(selected.args ?? []));
}

async function promptOptionalIdentityField(
    prompt: string,
    placeHolder: string,
): Promise<string | undefined> {
    const value = await vscode.window.showInputBox({
        prompt,
        placeHolder,
        ignoreFocusOut: true,
    });

    const trimmed = value?.trim();
    return trimmed ? trimmed : undefined;
}

async function ensureProjectRootReady(promptLabel = 'Select the Owlvex project root that defines the repo boundary for scans and AI context.'): Promise<vscode.Uri | undefined> {
    const current = await resolveProjectRootInfo();
    if (current.uri && current.isConfigured) {
        return current.uri;
    }

    vscode.window.showInformationMessage(`${PROFILE.displayLabel}: ${promptLabel}`);
    const selected = await promptForProjectRootSelection({
        title: 'Select Owlvex project root',
        openLabel: 'Use As Project Root',
    });
    return selected?.uri;
}

export function getProviderConnectionSettingKeys(providerId: string): string[] {
    switch (providerId) {
        case 'azure-foundry':
            return ['foundry.endpoint', 'foundry.model', 'foundry.deployments'];
        case 'anthropic':
            return ['anthropic.model'];
        case 'openai':
            return ['openai.model'];
        case 'mistral':
            return ['mistral.model'];
        case 'gemini':
            return ['gemini.model'];
        case 'groq':
            return ['groq.model'];
        case 'ollama':
            return ['ollama.host', 'ollama.model'];
        case 'custom':
            return ['custom.baseUrl', 'custom.model'];
        default:
            return [];
    }
}

export function providerAllowsOptionalApiKey(providerId: string): boolean {
    return providerId === 'custom';
}

export type ProviderApiKeyInputResolution =
    | { action: 'cancel' }
    | { action: 'keep' }
    | { action: 'store'; key: string }
    | { action: 'delete' }
    | { action: 'invalid' };

export function resolveProviderApiKeyInput(
    input: string | undefined,
    options: {
        hasExistingKey: boolean;
        allowBlank: boolean;
    },
): ProviderApiKeyInputResolution {
    if (input === undefined) {
        return { action: 'cancel' };
    }

    const trimmed = input.trim();
    if (trimmed) {
        return { action: 'store', key: trimmed };
    }

    if (options.hasExistingKey) {
        return { action: 'keep' };
    }

    if (options.allowBlank) {
        return { action: 'delete' };
    }

    return { action: 'invalid' };
}

export function resolveConnectedModelSelection(selectedModel: string, discoveredModels: string[]): string {
    const normalizedSelectedModel = selectedModel.trim();
    if (normalizedSelectedModel) {
        return normalizedSelectedModel;
    }

    return discoveredModels.find(model => model.trim())?.trim() ?? '';
}

async function resetProviderSettings(providerId: string): Promise<void> {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    for (const key of getProviderConnectionSettingKeys(providerId)) {
        await config.update(key, undefined, vscode.ConfigurationTarget.Workspace);
        await config.update(key, undefined, vscode.ConfigurationTarget.Global);
    }
}

export async function clearProviderConnection(
    providerId: string,
    secretStorage: Pick<vscode.SecretStorage, 'delete'>,
): Promise<void> {
    await resetProviderSettings(providerId);
    await secretStorage.delete(getProviderApiKeySecretName(providerId));

    // Clear the legacy Azure secret too so older installs do not keep a hidden duplicate.
    if (providerId === 'azure-foundry') {
        await secretStorage.delete(`${PROFILE.secretPrefix}.azure-foundry.apiKey`);
    }
}

async function chooseFallbackProviderId(registry: ProviderRegistry, removedProviderId: string): Promise<string> {
    for (const provider of registry.allProviders()) {
        if (provider.id === removedProviderId) {
            continue;
        }

        if (await provider.isConfigured()) {
            return provider.id;
        }
    }

    return 'openai';
}

async function readErrorResponse(res: Response, prefix: string): Promise<string> {
    const text = await res.text();
    if (!text.trim()) {
        return `${prefix}: HTTP ${res.status}`;
    }

    try {
        const parsed = JSON.parse(text);
        return parsed?.detail ? `${prefix}: ${parsed.detail}` : `${prefix}: HTTP ${res.status}`;
    } catch {
        return `${prefix}: ${text.trim().slice(0, 180)}`;
    }
}

async function readJsonResponse(res: Response, prefix: string): Promise<any> {
    const text = await res.text();
    try {
        return JSON.parse(text);
    } catch {
        throw new Error(text.trim() ? `${prefix}: ${text.trim().slice(0, 180)}` : prefix);
    }
}

async function registerTrackedAccessRequest(
    apiUrl: string,
    payload: RegisterTrackedAccessPayload,
): Promise<RegisterAccessResponse> {
    const response = await fetch(`${apiUrl}/v1/licences/register`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        throw new Error(await readErrorResponse(response, 'Registration failed'));
    }

    return await readJsonResponse(response, 'Registration response returned invalid JSON') as RegisterAccessResponse;
}

async function verifyTrackedAccessRequest(
    apiUrl: string,
    payload: { email: string; code: string },
): Promise<VerifyRegistrationResponse> {
    const response = await fetch(`${apiUrl}/v1/licences/verify-email`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        throw new Error(await readErrorResponse(response, 'Verification failed'));
    }

    return await readJsonResponse(response, 'Verification response returned invalid JSON') as VerifyRegistrationResponse;
}

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.workspace.registerTextDocumentContentProvider(OWLVEX_PREVIEW_SCHEME, new PreviewDocumentProvider()),
    );
    secrets = context.secrets;
    initializeSecretStorage(context.secrets);

    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const getConfiguredApiUrl = () => normalizeServiceUrl(
        vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('apiUrl', PROFILE.defaultApiUrl) || PROFILE.defaultApiUrl,
    );

    const licenceMgr = new LicenceManager(context.secrets, context.globalState);
    const previousSessionAt = context.globalState.get<string>(`${PROFILE.storagePrefix}.lastSessionAt`);
    let sessionScanCount = 0;
    let usefulnessFeedbackPrompted = false;
    const limitHitEventKeys = new Set<string>();
    const registry = new ProviderRegistry();
    const scanEngine = new ScanEngine(licenceMgr, registry, context.workspaceState);
    const rulePackClient = new RulePackClient(context.workspaceState);
    let currentRulePackContext: RulePackRuntimeContext = {
        mode: 'bundled',
        packIds: [],
    };
    const diagnostics = new DiagnosticsProvider();
    const statusBar = new StatusBar();
    const sidebar = new SidebarProvider();
    void migrateWorkspaceProviderSettingsToGlobalDefaults();
    const restoredScans = context.workspaceState.get<Array<{ scanId: string; result: ScanResult; targetLabel?: string; scannedAt?: string }>>(SCAN_STORE_KEY, []);
    for (const item of restoredScans) {
        scanStore.set(item.scanId, normalizeStoredScanRecord(item));
    }
    const restoredReports = context.workspaceState.get<StoredReportRecord[]>(REPORT_STORE_KEY, []);
    for (const item of restoredReports) {
        reportStore.set(item.reportId, normalizeStoredReportRecord(item));
    }
    const lastStoredScan = restoredScans[restoredScans.length - 1]?.result;
    if (lastStoredScan) {
        sidebar.refresh(lastStoredScan);
    }

    const persistScans = async () => {
        await context.workspaceState.update(SCAN_STORE_KEY, serializeScanStore());
    };
    const persistReports = async () => {
        await context.workspaceState.update(REPORT_STORE_KEY, serializeReportStore());
    };

    if (previousSessionAt) {
        void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'session_return', {
            previous_session_at: previousSessionAt,
        }, {
            registry,
            includeProviderModel: true,
            includeProject: true,
        });
    }
    void context.globalState.update(`${PROFILE.storagePrefix}.lastSessionAt`, new Date().toISOString());

    const maybePromptUsefulnessFeedback = async (
        info: LicenceInfo | null | undefined,
        metadata: Record<string, unknown>,
    ): Promise<void> => {
        if (!shouldPromptUsefulnessFeedback(info, sessionScanCount, usefulnessFeedbackPrompted)) {
            return;
        }

        usefulnessFeedbackPrompted = true;
        const choice = await vscode.window.showInformationMessage(
            buildUsefulnessPromptMessage(info),
            'Helpful',
            'Not yet',
        );

        if (choice === 'Helpful') {
            void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'feedback_positive', metadata, {
                registry,
                includeProviderModel: true,
                includeProject: true,
            });
        } else if (choice === 'Not yet') {
            void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'feedback_negative', metadata, {
                registry,
                includeProviderModel: true,
                includeProject: true,
            });
        }
    };

    const handleLimitHit = async (info: LicenceInfo): Promise<void> => {
        const limitKey = `${info.licenceId}:${info.usage.scansThisMonth}:${info.features.scansPerMonth ?? 'unlimited'}`;
        if (!limitHitEventKeys.has(limitKey)) {
            limitHitEventKeys.add(limitKey);
            void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'limit_hit', {
                plan: info.plan,
                scans_this_month: info.usage.scansThisMonth,
                scans_remaining: info.usage.scansRemaining,
                scans_per_month: info.features.scansPerMonth,
            }, {
                registry,
                includeProviderModel: true,
                includeProject: true,
            });
        }

        const choice = await vscode.window.showInformationMessage(
            buildScanLimitMessage(info),
            'Start Trial',
            'Later',
        );
        if (choice === 'Start Trial') {
            await vscode.commands.executeCommand(PROFILE.commands.registerAccess, 'trial');
        }
    };

    const ensureScanAllowedForSession = async (): Promise<LicenceInfo | null> => {
        const info = await ensureScanAllowed(licenceMgr, getConfiguredApiUrl);
        if (!info) {
            const action = await vscode.window.showInformationMessage(
                `${PROFILE.displayLabel}: A valid licence is required before scans can run. Use Free, Start Trial, or Enter Licence to continue.`,
                'Use Free',
                'Start Trial',
                'Enter Licence',
            );
            if (action === 'Use Free') {
                await vscode.commands.executeCommand(PROFILE.commands.registerAccess, 'free');
            } else if (action === 'Start Trial') {
                await vscode.commands.executeCommand(PROFILE.commands.registerAccess, 'trial');
            } else if (action === 'Enter Licence') {
                await vscode.commands.executeCommand(PROFILE.commands.enterLicence);
            }
            return null;
        }
        if (info && !canRunScan(info)) {
            await handleLimitHit(info);
            return null;
        }
        return info;
    };

    const refreshIdleStatus = () => statusBar.showIdle(licenceMgr.getCachedInfo());
    const refreshStoredKeyStatus = async () => {
        const storedKey = await licenceMgr.getKey().catch(() => undefined);
        if (storedKey) {
            statusBar.showStoredKeyPending();
        } else {
            statusBar.showUnlicensed();
        }
    };

    const currentEntitlement = (): PackEntitlement | undefined => {
        const info = licenceMgr.getCachedInfo();
        if (!info) {
            return undefined;
        }

        return {
            plan: info.plan,
            frameworks: info.features.frameworks,
        };
    };

    const applyRulePackContext = (result: ScanResult): ScanResult => ({
        ...result,
        packContext: {
            ...currentRulePackContext,
            packIds: [...currentRulePackContext.packIds],
        },
    });

    const appendRepoAiWarning = (
        items: Array<{ uri: vscode.Uri; result: ScanResult }>,
        warning: string,
    ): Array<{ uri: vscode.Uri; result: ScanResult }> => {
        if (!items.length) {
            return items;
        }

        return items.map((item, index) => index === 0
            ? {
                ...item,
                result: {
                    ...item.result,
                    warnings: [...(item.result.warnings ?? []), warning],
                },
            }
            : item,
        );
    };

    const maybeApplyRepoAiReview = async (
        items: Array<{ uri: vscode.Uri; result: ScanResult }>,
        scopeLabel: string,
    ): Promise<Array<{ uri: vscode.Uri; result: ScanResult }>> => {
        if (items.length < 2) {
            return items;
        }

        const baseResults = items.map(item => ({
            path: vscode.workspace.asRelativePath(item.uri, false) || path.basename(item.uri.fsPath),
            result: item.result,
        }));
        const candidateRefs = selectRepoAiCandidateRefs(baseResults, MAX_REPO_AI_REVIEW_CANDIDATES);
        if (!candidateRefs.length) {
            return items;
        }

        try {
            const provider = registry.getActive();
            const projectContext = await loadProjectContextInfo();
            const snippets = await Promise.all(candidateRefs.map(async ref => {
                const document = await vscode.workspace.openTextDocument(items[ref.resultIndex].uri);
                return {
                    ...ref,
                    snippet: extractRepoAiSnippet(document.getText(), ref.finding),
                };
            }));

            const response = await provider.complete({
                systemPrompt: 'You are Owlvex Repo AI. Review candidate findings across a bounded multi-file scan using only the provided project context, file summaries, and snippets. Support only when broader repo context materially strengthens the claim. Return JSON only.',
                userMessage: buildRepoAiReviewPrompt({
                    scopeLabel,
                    projectContext: projectContext.combined,
                    fileSummaries: summarizeRepoAiResults(baseResults),
                    candidates: snippets,
                }),
                model: provider.selectedModel,
                temperature: 0,
            });

            const reviews = parseRepoAiReviewResponse(response.content);
            const updated = applyRepoAiReviewSupport(baseResults, candidateRefs, reviews);
            return updated.map((item, index) => ({
                uri: items[index].uri,
                result: item.result,
            }));
        } catch (error: any) {
            return appendRepoAiWarning(
                items,
                `REPO_AI review unavailable: ${error.message}`,
            );
        }
    };

    const finalizeMultiFileResults = async (
        items: Array<{ uri: vscode.Uri; result: ScanResult }>,
        scopeLabel: string,
    ): Promise<Array<{ uri: vscode.Uri; result: ScanResult }>> => {
        const repoReviewed = await maybeApplyRepoAiReview(items, scopeLabel);
        return repoReviewed.map(item => ({
            uri: item.uri,
            result: applyRulePackContext(item.result),
        }));
    };

    const isRevocationLikeError = (error: unknown): boolean => {
        const message = String((error as any)?.message ?? '').toLowerCase();
        return [
            'licence key not found',
            'licence is inactive',
            'licence has expired',
            'http 401',
            'http 403',
        ].some(fragment => message.includes(fragment));
    };

    const purgeRulePackState = async () => {
        await rulePackClient.purgeCachedRulePacks();
        configureRulePackRuntime(undefined, undefined);
        configureFrameworkPackRuntime(undefined);
        currentRulePackContext = {
            mode: 'bundled',
            packIds: [],
        };
    };

    const hydrateRulePackRuntimeFromCache = (entitlement?: PackEntitlement) => {
        const manifestFreshness = rulePackClient.getCachedManifestFreshness(entitlement);
        const cachedIssuePack = rulePackClient.getCachedPack(ISSUE_PACK_ID, entitlement);
        const cachedMappingPack = rulePackClient.getCachedPack(ISSUE_MAPPING_PACK_ID, entitlement);
        const cachedRemediationPack = rulePackClient.getCachedPack(REMEDIATION_PACK_ID, entitlement);
        const cachedFrameworkPack = rulePackClient.getCachedPack(FRAMEWORK_PACK_ID, entitlement);
        configureRulePackRuntime(cachedIssuePack?.artifact, cachedMappingPack?.artifact, cachedRemediationPack?.artifact);
        configureFrameworkPackRuntime(cachedFrameworkPack?.artifact);
        currentRulePackContext = cachedIssuePack && cachedMappingPack
            ? {
                mode: 'cached',
                packIds: [
                    ISSUE_PACK_ID,
                    ISSUE_MAPPING_PACK_ID,
                    ...(cachedRemediationPack ? [REMEDIATION_PACK_ID] : []),
                    ...(cachedFrameworkPack ? [FRAMEWORK_PACK_ID] : []),
                ],
                fetchedAt: cachedIssuePack.fetched_at ?? cachedMappingPack.fetched_at ?? cachedRemediationPack?.fetched_at ?? cachedFrameworkPack?.fetched_at,
                manifestFreshness: manifestFreshness === 'missing' ? 'stale' : manifestFreshness,
            }
            : {
                mode: 'bundled',
                packIds: [],
            };
    };

    const refreshRulePackRuntime = async () => {
        const licenceKey = await licenceMgr.getKey();
        if (!licenceKey) {
            hydrateRulePackRuntimeFromCache();
            return;
        }

        const entitlement = currentEntitlement();

        let manifest;
        try {
            manifest = await rulePackClient.syncManifest(getConfiguredApiUrl(), licenceKey);
        } catch (error) {
            if (isRevocationLikeError(error)) {
                await purgeRulePackState();
            } else {
                hydrateRulePackRuntimeFromCache(entitlement);
            }
            return;
        }

        const requiredPackIds = new Set([ISSUE_PACK_ID, ISSUE_MAPPING_PACK_ID, REMEDIATION_PACK_ID, FRAMEWORK_PACK_ID]);
        const manifestById = new Map<string, PackManifestEntry>(
            manifest.packs
                .filter(entry => requiredPackIds.has(entry.pack_id))
                .map(entry => [entry.pack_id, entry]),
        );

        const fetchIfListed = async (packId: string): Promise<{ artifact?: PackArtifactResponse; source: 'fresh' | 'cached' | 'missing' }> => {
            const entry = manifestById.get(packId);
            if (!entry) {
                const cached = rulePackClient.getCachedPack(packId, entitlement);
                return {
                    artifact: cached,
                    source: cached ? 'cached' : 'missing',
                };
            }

            const cachedForCurrentManifest = rulePackClient.getCachedPackForManifest(entry, entitlement);
            if (cachedForCurrentManifest) {
                return {
                    artifact: cachedForCurrentManifest,
                    source: 'cached',
                };
            }

            try {
                return {
                    artifact: await rulePackClient.fetchPackArtifact(getConfiguredApiUrl(), licenceKey, entry),
                    source: 'fresh',
                };
            } catch {
                const cached = rulePackClient.getCachedPack(packId, entitlement);
                return {
                    artifact: cached,
                    source: cached ? 'cached' : 'missing',
                };
            }
        };

        const [issuePackResult, mappingPackResult, remediationPackResult, frameworkPackResult] = await Promise.all([
            fetchIfListed(ISSUE_PACK_ID),
            fetchIfListed(ISSUE_MAPPING_PACK_ID),
            fetchIfListed(REMEDIATION_PACK_ID),
            fetchIfListed(FRAMEWORK_PACK_ID),
        ]);
        const issuePack = issuePackResult.artifact;
        const mappingPack = mappingPackResult.artifact;
        const remediationPack = remediationPackResult.artifact;
        const frameworkPack = frameworkPackResult.artifact;

        configureRulePackRuntime(issuePack?.artifact, mappingPack?.artifact, remediationPack?.artifact);
        configureFrameworkPackRuntime(frameworkPack?.artifact);
        currentRulePackContext = issuePack && mappingPack
            ? {
                mode: issuePackResult.source === 'fresh'
                    && mappingPackResult.source === 'fresh'
                    && (!remediationPack || remediationPackResult.source === 'fresh')
                    && (!frameworkPack || frameworkPackResult.source === 'fresh')
                    ? 'fresh'
                    : 'cached',
                packIds: [
                    ISSUE_PACK_ID,
                    ISSUE_MAPPING_PACK_ID,
                    ...(remediationPack ? [REMEDIATION_PACK_ID] : []),
                    ...(frameworkPack ? [FRAMEWORK_PACK_ID] : []),
                ],
                fetchedAt: manifest.fetched_at,
                manifestFreshness: 'fresh',
            }
            : {
                mode: 'bundled',
                packIds: [],
            };
    };

    const persistLastReportSnapshot = async (snapshot: ReportSnapshot) => {
        await context.workspaceState.update(LAST_REPORT_SNAPSHOT_KEY, {
            ...snapshot,
            outputRoot: snapshot.outputRoot.toString(),
            results: snapshot.results.map(item => ({
                uri: item.uri.toString(),
                result: item.result,
            })),
        });
    };

    const restoreLastReportSnapshot = (): ReportSnapshot | undefined => {
        const raw = context.workspaceState.get<any>(LAST_REPORT_SNAPSHOT_KEY);
        if (!raw?.results?.length || !raw?.outputRoot) return undefined;
        return {
            targetLabel: raw.targetLabel,
            outputRoot: vscode.Uri.parse(raw.outputRoot),
            errors: raw.errors ?? [],
            results: raw.results.map((item: any) => ({
                uri: vscode.Uri.parse(item.uri),
                result: item.result as ScanResult,
            })),
        };
    };

    const normalizeScanHistoryPath = (uri: vscode.Uri): string => path.normalize(uri.fsPath).toLowerCase();

    const loadRecentScanSnapshots = (): Record<string, RecentScanSnapshot> => {
        const raw = context.workspaceState.get<Record<string, RecentScanSnapshot>>(RECENT_SCAN_SNAPSHOTS_KEY);
        return raw && typeof raw === 'object' ? raw : {};
    };

    const persistRecentScanSnapshots = async (snapshots: Record<string, RecentScanSnapshot>) => {
        await context.workspaceState.update(RECENT_SCAN_SNAPSHOTS_KEY, snapshots);
    };

    const buildProviderDisagreementProof = (result: ScanResult): ProviderDisagreementProof => {
        const evidenceFinding = result.findings.find(finding => finding.evidenceContract);
        if (!evidenceFinding) {
            return {
                verdict: result.findings.length ? 'UNRESOLVED' : 'UNRESOLVED',
                reason: result.findings.length
                    ? 'Provider disagreement exists, but no structured evidence contract is available yet.'
                    : 'Provider disagreement exists, and this scan has no findings to prove or disprove.',
            };
        }

        const evidence = evidenceFinding.evidenceContract;
        if (evidence?.verdict === 'guarded' || evidence?.guard?.status === 'present') {
            return {
                verdict: 'CONTRADICTED_BY_GUARD',
                reason: 'Structured evidence shows a guard that may defeat the claimed issue.',
                findingId: evidenceFinding.id,
                issueType: evidence.issueType,
                source: evidence.source?.expression,
                sink: evidence.sink?.expression,
                guard: evidence.guard?.expression ?? evidence.guard?.label,
            };
        }

        if (evidenceFinding.provenance === 'deterministic' && evidence?.guard?.status === 'missing') {
            return {
                verdict: 'PROVEN_BY_SINK',
                reason: 'Deterministic evidence confirms source-to-sink flow with no recognized guard.',
                findingId: evidenceFinding.id,
                issueType: evidence.issueType,
                source: evidence.source?.expression,
                sink: evidence.sink?.expression,
                guard: evidence.guard?.label,
            };
        }

        return {
            verdict: 'AI_ONLY',
            reason: 'AI returned structured evidence, but deterministic sink proof is not available yet.',
            findingId: evidenceFinding.id,
            issueType: evidence?.issueType,
            source: evidence?.source?.expression,
            sink: evidence?.sink?.expression,
            guard: evidence?.guard?.expression ?? evidence?.guard?.label,
        };
    };

    const annotateProviderComparisonNotes = async (
        results: Array<{ uri: vscode.Uri; result: ScanResult }>,
    ): Promise<Array<{ uri: vscode.Uri; result: ScanResult }>> => {
        const snapshots = loadRecentScanSnapshots();
        const annotated = results.map(item => {
            const key = normalizeScanHistoryPath(item.uri);
            const previous = snapshots[key];
            const current: RecentScanSnapshot = {
                provider: item.result.provider || 'unknown provider',
                model: item.result.model || 'unknown model',
                findingCount: item.result.findings.length,
                score: item.result.score,
            };
            const providerChanged = Boolean(previous)
                && (previous!.provider !== current.provider || previous!.model !== current.model);
            const label = vscode.workspace.asRelativePath(item.uri, false);
            const notes: string[] = [];
            const proofs: ProviderDisagreementProof[] = [];

            if (previous && providerChanged && previous.findingCount === 0 && current.findingCount > 0) {
                notes.push(`Provider disagreement: ${previous.provider} / ${previous.model} previously reported 0 findings for ${label}; ${current.provider} / ${current.model} now reports ${current.findingCount}. Treat clean scans as provider/model-scoped evidence.`);
                proofs.push(buildProviderDisagreementProof(item.result));
            } else if (previous && providerChanged && previous.findingCount > 0 && current.findingCount === 0) {
                notes.push(`Provider-scoped clean result: ${current.provider} / ${current.model} reports 0 findings for ${label}, while ${previous.provider} / ${previous.model} previously reported ${previous.findingCount}. Consider a second-provider review before calling the file clean.`);
                proofs.push(buildProviderDisagreementProof(item.result));
            } else if (!previous && current.findingCount === 0) {
                notes.push(`Clean result scope: ${current.provider} / ${current.model} reported 0 findings for ${label}; this is not proof of absence across other models or deeper review.`);
            }

            snapshots[key] = current;
            return {
                ...item,
                result: {
                    ...item.result,
                    providerComparisonNotes: notes.length
                        ? [...(item.result.providerComparisonNotes ?? []), ...notes]
                        : item.result.providerComparisonNotes,
                    providerDisagreementProofs: proofs.length
                        ? [...(item.result.providerDisagreementProofs ?? []), ...proofs]
                        : item.result.providerDisagreementProofs,
                },
            };
        });

        await persistRecentScanSnapshots(snapshots);
        return annotated;
    };

    const createAndOpenReport = async (snapshot: ReportSnapshot, reportVariant: ReportVariant = 'full') => {
        const reportStartedAt = Date.now();
        const safeSnapshot = await normalizeReportSnapshot(snapshot);
        let reportUri: vscode.Uri;
        try {
            reportUri = await generateReportFromSnapshot(safeSnapshot.outputRoot, safeSnapshot, { variant: reportVariant });
        } catch (error: any) {
            emitDevWorkflowLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'report_failed', {
                status: 'failed',
                report_variant: reportVariant,
                target_label: safeSnapshot.targetLabel,
                file_count: safeSnapshot.results.length,
                finding_count: safeSnapshot.results.reduce((total, item) => total + item.result.findings.length, 0),
                duration_ms: Date.now() - reportStartedAt,
                stage: 'report_generation',
                error_kind: classifyTelemetryError(error),
            });
            throw error;
        }
        const reportDoc = await vscode.workspace.openTextDocument(reportUri);
        await vscode.window.showTextDocument(reportDoc, { preview: false });

        const providerNames = [...new Set(safeSnapshot.results.map(item => item.result.provider))].join(', ') || 'unknown';
        const modelNames = [...new Set(safeSnapshot.results.map(item => item.result.model))].join(', ') || 'unknown';
        const packContext = safeSnapshot.results[0]?.result.packContext;
        const averageScore = safeSnapshot.results.length
            ? safeSnapshot.results.reduce((total, item) => total + item.result.score, 0) / safeSnapshot.results.length
            : 0;
        const totalFindings = safeSnapshot.results.reduce((total, item) => total + item.result.findings.length, 0);
        const warningCount = safeSnapshot.results.reduce((total, item) => total + (item.result.warnings ?? []).length, 0);

        storeReportResult({
            reportId: createHash('sha256').update(`${reportUri.toString()}|${Date.now()}`).digest('hex').slice(0, 16),
            reportUri: reportUri.toString(),
            reportFileName: path.basename(reportUri.fsPath),
            targetLabel: safeSnapshot.targetLabel,
            createdAt: new Date().toISOString(),
            fileCount: safeSnapshot.results.length,
            totalFindings,
            averageScore,
            providers: [...new Set(safeSnapshot.results.map(item => item.result.provider).filter(Boolean))],
            models: [...new Set(safeSnapshot.results.map(item => item.result.model).filter(Boolean))],
            results: safeSnapshot.results.map(item => ({
                uri: item.uri.toString(),
                result: item.result,
            })),
        });
        await persistReports();

        statusBar.showResult({
            score: averageScore,
            model: modelNames,
            findings: safeSnapshot.results.flatMap(item => item.result.findings),
            packContext,
        });
        vscode.window.showInformationMessage(
            `${PROFILE.displayLabel}: ${reportVariant === 'summary' ? 'Summary report' : 'Full evidence report'} created for ${safeSnapshot.results.length} file(s) with ${totalFindings} finding(s) using ${providerNames}/${modelNames}.${warningCount ? ` ${warningCount} warning(s) were captured.` : ''}`
        );
        emitDevWorkflowLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'report_created', {
            status: 'completed',
            report_variant: reportVariant,
            target_label: safeSnapshot.targetLabel,
            file_count: safeSnapshot.results.length,
            finding_count: totalFindings,
            warning_count: warningCount,
            average_score: averageScore,
            duration_ms: Date.now() - reportStartedAt,
        });

        return {
            reportUri,
            averageScore,
            providers: providerNames,
            models: modelNames,
            reportVariant,
            summary: {
                completed: safeSnapshot.results.length,
                totalFindings,
                errors: safeSnapshot.errors,
                results: safeSnapshot.results,
            },
        };
    };

    const normalizeReportSnapshot = async (snapshot: ReportSnapshot): Promise<ReportSnapshot> => {
        const resolved = await resolveReportOutputRoot(snapshot.outputRoot, snapshot.results);
        const sameRoot = snapshot.outputRoot?.scheme === 'file'
            && path.normalize(snapshot.outputRoot.fsPath) === path.normalize(resolved.root.fsPath);
        if (sameRoot && !resolved.warning) {
            return snapshot;
        }

        return {
            ...snapshot,
            outputRoot: resolved.root,
            errors: resolved.warning
                ? [...snapshot.errors, resolved.warning]
                : snapshot.errors,
        };
    };

    const compareStoredReports = async (
        compareApiUrl: string,
        licenceKey: string,
        reportA: StoredReportRecord,
        reportB: StoredReportRecord,
    ): Promise<void> => {
        const orderedReports = orderReportsForComparison(reportA, reportB);
        const baselineReport = orderedReports.baseline;
        const currentReport = orderedReports.current;
        const scanAId = getReportComparisonAnchorScanId(baselineReport);
        const scanBId = getReportComparisonAnchorScanId(currentReport);
        if (!scanAId || !scanBId) {
            throw new Error('One of the selected reports does not contain stored scan IDs, so it cannot be compared yet.');
        }

        const findingsA = baselineReport.results.flatMap(item => item.result.findings);
        const findingsB = currentReport.results.flatMap(item => item.result.findings);

        const res = await fetch(`${compareApiUrl}/v1/scans/compare`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Licence-Key': licenceKey,
            },
            body: JSON.stringify({
                scan_a_id: scanAId,
                scan_b_id: scanBId,
                findings_a: findingsA.map(f => ({
                    issue_id: f.canonicalId,
                    canonical_title: f.canonicalTitle,
                    line: f.line,
                    framework: f.framework,
                    rule_code: f.ruleCode,
                    severity: f.severity,
                    title: f.title,
                })),
                findings_b: findingsB.map(f => ({
                    issue_id: f.canonicalId,
                    canonical_title: f.canonicalTitle,
                    line: f.line,
                    framework: f.framework,
                    rule_code: f.ruleCode,
                    severity: f.severity,
                    title: f.title,
                })),
                score_a: baselineReport.averageScore,
                score_b: currentReport.averageScore,
            }),
        });

        if (!res.ok) {
            throw new Error(await readErrorResponse(res, 'Compare request failed'));
        }

        const diff = await readJsonResponse(res, 'Compare response returned invalid JSON');
        const scoreChange = diff.score_change > 0
            ? `+${diff.score_change.toFixed(1)}`
            : diff.score_change.toFixed(1);

        const panel = vscode.window.createWebviewPanel(
            PROFILE.comparisonPanelId,
            `${PROFILE.displayLabel}: Report Comparison`,
            vscode.ViewColumn.One,
            {},
        );

        panel.webview.html = buildComparisonHtmlV2(diff, scoreChange, {
            baseline: baselineReport,
            current: currentReport,
            wasReordered: orderedReports.wasReordered,
        });
    };

    const emitExtensionUsageEvent = (eventName: UsageEventName, metadata: Record<string, unknown> = {}): void => {
        if (DEV_OBSERVABILITY_USAGE_EVENTS.has(eventName)) {
            if (!isDevObservabilityTelemetryEnabled(licenceMgr.getCachedInfo())) {
                return;
            }
            metadata = {
                telemetry_profile: 'dev_observability',
                ...metadata,
            };
        }

        void trackUsageEvent(licenceMgr, getConfiguredApiUrl, eventName, metadata, {
            registry,
            includeProviderModel: true,
            includeProject: true,
        });
    };

    const chatView = new ChatViewProvider(registry, context.workspaceState, licenceMgr, emitExtensionUsageEvent);
    hydrateRulePackRuntimeFromCache();

    vscode.window.registerTreeDataProvider(PROFILE.findingsViewId, sidebar);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(ChatViewProvider.viewType, chatView, {
            webviewOptions: {
                retainContextWhenHidden: true,
            },
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.discussFinding, async (finding?: any) => {
            if (!finding) {
                await chatView.show();
                return;
            }

            const licenceInfo = await resolveLicenceInfoForAccess(licenceMgr, getConfiguredApiUrl);
            if (!hasAiAssistantAccess(licenceInfo)) {
                vscode.window.showInformationMessage(buildPlanUpgradeMessage('assistant'));
                return;
            }

            void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'finding_viewed', buildFindingUsageMetadata(finding), {
                registry,
                includeProviderModel: true,
                includeProject: true,
            });
            await chatView.discussFinding(finding);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.generateFixPreview, async (finding?: any) => {
            if (!finding) {
                await chatView.show();
                return;
            }

            const licenceInfo = await resolveLicenceInfoForAccess(licenceMgr, getConfiguredApiUrl);
            if (!hasAiAssistantAccess(licenceInfo)) {
                vscode.window.showInformationMessage(buildPlanUpgradeMessage('fix'));
                return;
            }

            void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'fix_viewed', buildFindingUsageMetadata(finding), {
                registry,
                includeProviderModel: true,
                includeProject: true,
            });
            await chatView.generateFixPreview(finding);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.applyFixPreview, async () => {
            await chatView.applyPendingFixPreview();
        })
    );

    licenceMgr.validate(getConfiguredApiUrl()).then(() => {
        refreshIdleStatus();
        void refreshRulePackRuntime();
    }).catch(async (error) => {
        if (isRevocationLikeError(error)) {
            licenceMgr.clearCachedInfo();
            await purgeRulePackState();
            statusBar.showUnlicensed();
        } else {
            hydrateRulePackRuntimeFromCache();
            await refreshStoredKeyStatus();
        }
    });

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.configureBackend, async () => {
            const currentApiUrl = getConfiguredApiUrl();
            const entered = await vscode.window.showInputBox({
                prompt: 'Enter an Owlvex backend override URL for this VS Code profile',
                placeHolder: PROFILE.defaultApiUrl,
                value: currentApiUrl,
                ignoreFocusOut: true,
                validateInput: (value) => {
                    const trimmed = value.trim();
                    if (!trimmed) {
                        return 'The backend URL is required.';
                    }

                    try {
                        const parsed = new URL(normalizeServiceUrl(trimmed));
                        if (!/^https?:$/i.test(parsed.protocol)) {
                            return 'Use an http or https backend URL.';
                        }
                        return undefined;
                    } catch {
                        return 'Enter a valid backend URL.';
                    }
                },
            });

            if (!entered) {
                return;
            }

            const normalizedApiUrl = normalizeServiceUrl(entered);
            await persistProviderSetting('apiUrl', normalizedApiUrl);

            const backend = await testBackendConnection(normalizedApiUrl);
            if (!backend.success) {
                vscode.window.showWarningMessage(
                    `${PROFILE.displayLabel}: Backend override saved, but the health check failed. ${backend.message ?? 'Check the URL and try again.'}`,
                );
                return;
            }

            const licenceKey = await licenceMgr.getKey();
            if (!licenceKey) {
                await promptOnboardingChoices(
                    `${PROFILE.displayLabel}: Backend override connected (${backend.latencyMs}ms).\n${buildBackendConnectionSummary(normalizedApiUrl)}\nNext step: register Free, start Trial, or enter a licence key.`,
                    buildBackendConnectedNoLicenceChoices(),
                );
                return;
            }

            try {
                const info = await licenceMgr.validate(normalizedApiUrl);
                refreshIdleStatus();
                void refreshRulePackRuntime();
                await promptOnboardingChoices(
                    `${PROFILE.displayLabel}: Backend override connected (${backend.latencyMs}ms) and ${buildLicenceStatusSummary(info)}.\n${buildPlanNextStepGuidance(info).join('\n')}`,
                    buildBackendAndLicenceReadyChoices(),
                );
            } catch (error: any) {
                if (isRevocationLikeError(error)) {
                    licenceMgr.clearCachedInfo();
                    await purgeRulePackState();
                    statusBar.showUnlicensed();
                } else {
                    await refreshStoredKeyStatus();
                }
                vscode.window.showWarningMessage(
                    `${PROFILE.displayLabel}: Backend override connected (${backend.latencyMs}ms), but licence validation failed. ${error.message}`,
                );
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.showOnboarding, async () => {
            const projectRoot = await resolveProjectRootInfo();
            const licenceKey = await licenceMgr.getKey().catch(() => undefined);
            const cachedInfo = licenceMgr.getCachedInfo();
            const provider = registry.getActive();
            const providerConfigured = await provider.isConfigured().catch(() => false);

            let licenceReady = Boolean(cachedInfo);
            let licenceSummary = cachedInfo
                ? buildLicenceStatusSummary(cachedInfo)
                : licenceKey
                    ? 'Stored key found; run Test Setup to validate it.'
                    : 'No licence or registration yet.';

            if (licenceKey && !cachedInfo) {
                try {
                    const info = await licenceMgr.validate(getConfiguredApiUrl());
                    licenceReady = true;
                    licenceSummary = buildLicenceStatusSummary(info);
                    refreshIdleStatus();
                    void refreshRulePackRuntime();
                } catch (error: any) {
                    licenceReady = false;
                    licenceSummary = `Stored key could not be validated: ${error.message}`;
                    if (isRevocationLikeError(error)) {
                        licenceMgr.clearCachedInfo();
                        await purgeRulePackState();
                        statusBar.showUnlicensed();
                    }
                }
            }

            const nextStep = !licenceReady
                ? 'Register Free, start Trial, or enter a licence key.'
                : !providerConfigured
                    ? 'Configure your LLM provider for AI review and fix previews.'
                    : !projectRoot.isConfigured
                        ? 'Select a project root if this workspace contains more than one app.'
                        : 'Run a scan and open the Summary report.';

            const actions: OnboardingActionChoice[] = [];
            if (!licenceReady) {
                actions.push(...buildBackendConnectedNoLicenceChoices());
            } else {
                if (!providerConfigured) {
                    actions.push({
                        label: 'Configure LLM',
                        command: PROFILE.commands.setupAI,
                    });
                }
                actions.push({
                    label: 'Scan Changed Files',
                    command: PROFILE.commands.scanChangedFiles,
                });
                actions.push({
                    label: 'Scan Workspace',
                    command: PROFILE.commands.scanWorkspace,
                });
            }
            if (!projectRoot.isConfigured) {
                actions.push({
                    label: 'Select Project Root',
                    command: PROFILE.commands.selectProjectRoot,
                });
            }

            await promptOnboardingChoices(
                [
                    `${PROFILE.displayLabel}: Onboarding status.`,
                    buildBackendConnectionSummary(getConfiguredApiUrl()),
                    `Licence: ${licenceSummary}`,
                    `LLM: ${providerConfigured ? `${provider.name} configured (${provider.selectedModel})` : `${provider.name} not configured`}`,
                    `Project root: ${projectRoot.summary}`,
                    `Next step: ${nextStep}`,
                ].join('\n'),
                actions,
            );
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.selectProjectRoot, async () => {
            const selected = await promptForProjectRootSelection({
                title: 'Select Owlvex project root',
                openLabel: 'Use As Project Root',
            });
            if (!selected?.uri) {
                return;
            }

            vscode.window.showInformationMessage(
                `${PROFILE.displayLabel}: Project root set to ${selected.label}. Repo scans and repo AI context will stay inside this boundary.`,
            );
            void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'project_root_selected', {}, {
                includeProject: true,
            });
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.registerAccess, async (requestedPlan?: 'free' | 'trial') => {
            const selectedPlan = requestedPlan ?? await (async (): Promise<'free' | 'trial' | undefined> => {
                const picked = await vscode.window.showQuickPick(
                    [
                        {
                            label: 'Free',
                            description: 'Deterministic scans and reports with capped usage',
                            plan: 'free' as const,
                        },
                        {
                            label: 'Trial',
                            description: '7-day full workflow with AI assistant and fix previews',
                            plan: 'trial' as const,
                        },
                    ],
                    {
                        title: 'Register Owlvex access',
                        placeHolder: 'Choose how you want to start',
                        ignoreFocusOut: true,
                    },
                );
                return picked?.plan;
            })();

            if (!selectedPlan) {
                return;
            }

            const savePendingRegistration = async (registration: RegisterAccessResponse): Promise<void> => {
                await context.globalState.update(PENDING_REGISTRATION_KEY, {
                    ...registration,
                    updated_at: new Date().toISOString(),
                } satisfies PendingRegistrationState);
            };

            const clearPendingRegistration = async (): Promise<void> => {
                await context.globalState.update(PENDING_REGISTRATION_KEY, undefined);
            };

            let pendingRegistration = context.globalState.get<PendingRegistrationState>(PENDING_REGISTRATION_KEY);
            if (pendingRegistration && pendingRegistration.plan !== selectedPlan) {
                pendingRegistration = undefined;
            }

            if (pendingRegistration) {
                const resumeChoice = await vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: ${pendingRegistration.plan} registration is already pending for ${pendingRegistration.email}. Enter the verification code or use a different email.`,
                    'Enter Code',
                    'Resend Code',
                    'Use Different Email',
                    'Cancel',
                );

                if (resumeChoice === 'Enter Code') {
                    const verified = await completeTrackedRegistrationVerification(
                        getConfiguredApiUrl(),
                        pendingRegistration,
                        savePendingRegistration,
                    );
                    if (!verified) {
                        return { status: 'pending', email: pendingRegistration.email, plan: selectedPlan };
                    }
                    await licenceMgr.storeKey(verified.licence_key);
                    await clearPendingRegistration();
                    const info = await licenceMgr.validate(getConfiguredApiUrl());
                    await promptOnboardingChoices(
                        `${PROFILE.displayLabel}: ${buildRegistrationSuccessMessage(selectedPlan, verified.email, info)}`,
                        buildRegistrationCompletionChoices(),
                    );
                    refreshIdleStatus();
                    void refreshRulePackRuntime();
                    return { status: 'completed', email: verified.email, plan: selectedPlan };
                }

                if (resumeChoice === 'Resend Code') {
                    try {
                        const registration = await registerTrackedAccessRequest(getConfiguredApiUrl(), {
                            email: pendingRegistration.email,
                            plan: pendingRegistration.plan,
                        });
                        await savePendingRegistration(registration);
                        vscode.window.showInformationMessage(
                            `${PROFILE.displayLabel}: ${buildVerificationPromptMessage(registration)}`,
                        );
                        const verified = await completeTrackedRegistrationVerification(
                            getConfiguredApiUrl(),
                            registration,
                            savePendingRegistration,
                        );
                        if (!verified) {
                            return { status: 'pending', email: registration.email, plan: selectedPlan };
                        }
                        await licenceMgr.storeKey(verified.licence_key);
                        await clearPendingRegistration();
                        const info = await licenceMgr.validate(getConfiguredApiUrl());
                        await promptOnboardingChoices(
                            `${PROFILE.displayLabel}: ${buildRegistrationSuccessMessage(selectedPlan, verified.email, info)}`,
                            buildRegistrationCompletionChoices(),
                        );
                        refreshIdleStatus();
                        void refreshRulePackRuntime();
                        return { status: 'completed', email: verified.email, plan: selectedPlan };
                    } catch (error: any) {
                        vscode.window.showWarningMessage(`${PROFILE.displayLabel}: ${error.message}`);
                        return { status: 'pending', email: pendingRegistration.email, plan: selectedPlan };
                    }
                }

                if (resumeChoice !== 'Use Different Email') {
                    return { status: 'pending', email: pendingRegistration.email, plan: selectedPlan };
                }

                await clearPendingRegistration();
            }

            const email = await vscode.window.showInputBox({
                prompt: selectedPlan === 'trial'
                    ? 'Enter your email to start a tracked 7-day Owlvex trial'
                    : 'Enter your email to register Owlvex Free access',
                placeHolder: 'you@company.com',
                ignoreFocusOut: true,
                validateInput: (value) => /\S+@\S+\.\S+/.test(value.trim()) ? undefined : 'Enter a valid email address.',
            });
            if (!email) {
                return { status: 'cancelled', plan: selectedPlan };
            }

            const name = await promptOptionalIdentityField(
                'Enter your name (optional)',
                'Jane Doe',
            );
            const company = await promptOptionalIdentityField(
                'Enter your company or team name (optional)',
                'Acme',
            );

            try {
                const projectRoot = await resolveProjectRootInfo();
                const registration = await registerTrackedAccessRequest(getConfiguredApiUrl(), {
                    email: email.trim(),
                    plan: selectedPlan,
                    name,
                    company,
                });
                await savePendingRegistration(registration);

                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: ${buildVerificationPromptMessage(registration)}`,
                );
                const verified = await completeTrackedRegistrationVerification(
                    getConfiguredApiUrl(),
                    registration,
                    savePendingRegistration,
                );
                if (!verified) {
                    return { status: 'pending', email: registration.email, plan: selectedPlan };
                }
                await licenceMgr.storeKey(verified.licence_key);
                await clearPendingRegistration();
                void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'registration_verified', {
                    plan: selectedPlan,
                    delivery: registration.delivery,
                    has_project_root: Boolean(projectRoot.uri),
                    project_root_configured: projectRoot.isConfigured,
                }, {
                    includeProject: true,
                });
                const info = await licenceMgr.validate(getConfiguredApiUrl());
                await promptOnboardingChoices(
                    `${PROFILE.displayLabel}: ${buildRegistrationSuccessMessage(selectedPlan, verified.email, info)}`,
                    buildRegistrationCompletionChoices(),
                );
                refreshIdleStatus();
                void refreshRulePackRuntime();
                return { status: 'completed', email: verified.email, plan: selectedPlan };
            } catch (error: any) {
                if (isRevocationLikeError(error)) {
                    licenceMgr.clearCachedInfo();
                    await purgeRulePackState();
                }
                vscode.window.showWarningMessage(`${PROFILE.displayLabel}: ${error.message}`);
                await refreshStoredKeyStatus();
                return { status: 'failed', error: error.message, plan: selectedPlan };
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.enterLicence, async () => {
            const key = await vscode.window.showInputBox({
                prompt: 'Enter your Owlvex licence key',
                placeHolder: 'owlvex_lic_...',
                ignoreFocusOut: true,
                password: true,
            });
            if (!key) return;

            await licenceMgr.storeKey(key);
            try {
                const info = await licenceMgr.validate(getConfiguredApiUrl());
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel} activated - ${buildLicenceStatusSummary(info)}\n${buildPlanNextStepGuidance(info).join('\n')}`
                );
                refreshIdleStatus();
                void refreshRulePackRuntime();
            } catch (error: any) {
                if (isRevocationLikeError(error)) {
                    licenceMgr.clearCachedInfo();
                    await purgeRulePackState();
                }
                vscode.window.showErrorMessage(`Licence validation failed: ${error.message}`);
                await refreshStoredKeyStatus();
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.removeLicence, async () => {
            const storedKey = await licenceMgr.getKey();
            if (!storedKey) {
                licenceMgr.clearCachedInfo();
                await purgeRulePackState();
                statusBar.showUnlicensed();
                vscode.window.showInformationMessage(`${PROFILE.displayLabel}: No stored licence key was found.`);
                return;
            }

            await licenceMgr.deleteKey();
            licenceMgr.clearCachedInfo();
            await purgeRulePackState();
            statusBar.showUnlicensed();

            vscode.window.showInformationMessage(
                `${PROFILE.displayLabel}: Removed the stored licence key for this profile. You can now re-register or enter a different licence.`,
                'Use Free',
                'Start Trial',
                'Enter Licence',
            ).then(async (action) => {
                if (action === 'Use Free') {
                    await vscode.commands.executeCommand(PROFILE.commands.registerAccess, 'free');
                } else if (action === 'Start Trial') {
                    await vscode.commands.executeCommand(PROFILE.commands.registerAccess, 'trial');
                } else if (action === 'Enter Licence') {
                    await vscode.commands.executeCommand(PROFILE.commands.enterLicence);
                }
            });
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.toggleTelemetry, async () => {
            const licenceKey = await licenceMgr.getKey();
            if (!licenceKey) {
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: Enter a paid licence before managing telemetry settings.`,
                    'Enter Licence',
                ).then(async action => {
                    if (action === 'Enter Licence') {
                        await vscode.commands.executeCommand(PROFILE.commands.enterLicence);
                    }
                });
                return;
            }

            let info: LicenceInfo;
            try {
                info = await licenceMgr.validate(getConfiguredApiUrl());
            } catch (error: any) {
                vscode.window.showWarningMessage(`${PROFILE.displayLabel}: ${error.message}`);
                await refreshStoredKeyStatus();
                return;
            }

            if (!info.features.telemetryOptOut) {
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: ${info.plan === 'trial' ? 'Trial' : 'Free'} access requires product telemetry for activation, quotas, and abuse prevention.`,
                );
                return;
            }

            const currentlyEnabled = info.features.telemetryEnabled;
            const choice = await vscode.window.showQuickPick(
                [
                    {
                        label: currentlyEnabled ? 'Disable Product Telemetry' : 'Enable Product Telemetry',
                        description: currentlyEnabled
                            ? 'Keep minimal licensing and quota checks, but stop optional product usage events.'
                            : 'Resume optional product usage events for this paid licence.',
                        enabled: !currentlyEnabled,
                    },
                    {
                        label: currentlyEnabled ? 'Keep Product Telemetry Enabled' : 'Keep Product Telemetry Disabled',
                        description: currentlyEnabled
                            ? 'Leave the current telemetry setting unchanged.'
                            : 'Leave optional product telemetry disabled.',
                        enabled: currentlyEnabled,
                    },
                ],
                {
                    title: 'Owlvex Telemetry Preference',
                    placeHolder: currentlyEnabled
                        ? 'Disable optional product telemetry for this paid licence?'
                        : 'Enable optional product telemetry for this paid licence?',
                    ignoreFocusOut: true,
                },
            );

            if (!choice || choice.enabled === currentlyEnabled) {
                return;
            }

            try {
                const updated = await updateTelemetryPreferenceRequest(getConfiguredApiUrl(), licenceKey, choice.enabled);
                const refreshed = await licenceMgr.validate(getConfiguredApiUrl());
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: ${updated.telemetry_enabled ? 'Enabled' : 'Disabled'} optional product telemetry for ${refreshed.plan}.`,
                );
                refreshIdleStatus();
            } catch (error: any) {
                vscode.window.showWarningMessage(`${PROFILE.displayLabel}: ${error.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.selectFrameworks, async () => {
            const currentSelection = config.get<string[]>('frameworks', ['OWASP', 'STRIDE']);
            let allowedFrameworks = licenceMgr.getCachedInfo()?.features.frameworks;
            if (!allowedFrameworks?.length) {
                try {
                    const info = await licenceMgr.validate(getConfiguredApiUrl());
                    allowedFrameworks = info.features.frameworks;
                } catch {
                    allowedFrameworks = FRAMEWORK_CATALOG.map(item => item.code);
                }
            }

            const availableFrameworks = FRAMEWORK_CATALOG.filter(item => allowedFrameworks?.includes(item.code));
            if (!availableFrameworks.length) {
                vscode.window.showWarningMessage(`${PROFILE.displayLabel}: No frameworks are available for this licence.`);
                return;
            }

            const picked = await vscode.window.showQuickPick(
                availableFrameworks.map(item => ({
                    label: item.code,
                    description: `${item.name} ${item.version}`,
                    detail: item.description,
                    picked: currentSelection.includes(item.code),
                })),
                {
                    canPickMany: true,
                    placeHolder: 'Select one or more frameworks for Owlvex scans and reports',
                    title: 'Owlvex Framework Selection',
                },
            );

            if (!picked) return;
            if (!picked.length) {
                vscode.window.showWarningMessage(`${PROFILE.displayLabel}: Select at least one framework.`);
                return;
            }

            const selectedCodes = picked.map(item => item.label);
            await vscode.workspace
                .getConfiguration(PROFILE.configSection)
                .update('frameworks', selectedCodes, getFrameworkConfigurationTarget());

            vscode.window.showInformationMessage(
                `${PROFILE.displayLabel}: Frameworks set to ${formatFrameworkSummary(selectedCodes)}`
            );
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanFile, async (requestedUri?: vscode.Uri): Promise<ScanFileCommandResult> => {
            const allowed = await ensureScanAllowedForSession();
            if (!allowed) {
                return { status: 'cancelled' };
            }
            const fileUri = await resolveScanFileTarget(requestedUri);
            if (!fileUri) {
                return { status: 'cancelled' };
            }

            const document = await vscode.workspace.openTextDocument(fileUri);
            const editor = await vscode.window.showTextDocument(document, { preview: false });

            statusBar.showScanning();
            diagnostics.clear(editor.document.uri);
            sidebar.clear();
            const scanStartedAt = Date.now();
            emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_started', {
                scope: 'current_file',
                startedAt: scanStartedAt,
                fileCount: 1,
                status: 'started',
            });

            try {
                const [annotated] = await annotateProviderComparisonNotes([{
                    uri: editor.document.uri,
                    result: applyRulePackContext(await scanEngine.scanDocument(editor.document)),
                }]);
                const result = annotated.result;
                storeScanResult(result.scanId, result, vscode.workspace.asRelativePath(editor.document.uri, false));
                await persistScans();
                await persistLastReportSnapshot({
                    targetLabel: vscode.workspace.asRelativePath(editor.document.uri, false),
                    outputRoot: vscode.Uri.file(path.dirname(editor.document.uri.fsPath)),
                    errors: [],
                    results: [{ uri: editor.document.uri, result }],
                });
                diagnostics.applyFindings(editor.document, result.findings);
                sidebar.refresh(result);
                statusBar.showResult(result);
                chatView.setLastScanTarget(`File: ${vscode.workspace.asRelativePath(editor.document.uri, false)}`);
                sessionScanCount += 1;
                void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'scan_run', {
                    scope: 'file',
                    file_count: 1,
                    finding_count: result.findings.length,
                }, {
                    registry,
                    includeProviderModel: true,
                    includeProject: true,
                });
                emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_completed', {
                    scope: 'current_file',
                    startedAt: scanStartedAt,
                    fileCount: 1,
                    findingCount: result.findings.length,
                    status: 'completed',
                });
                if (sessionScanCount === 2) {
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'second_scan', { scope: 'file' }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                }
                void maybePromptUsefulnessFeedback(allowed, {
                    scope: 'file',
                    finding_count: result.findings.length,
                });

                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: File risk ${result.score.toFixed(1)}/10 - ${result.findings.length} finding(s)${(result.warnings ?? []).length ? ` (${(result.warnings ?? []).length} warning(s))` : ''}`
                );

                return { status: 'completed', uri: editor.document.uri, result };
            } catch (error: any) {
                emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                    scope: 'current_file',
                    startedAt: scanStartedAt,
                    fileCount: 1,
                    status: 'failed',
                    stage: 'provider_call',
                    errorKind: classifyTelemetryError(error),
                });
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanSelectedFiles, async (requestedUris?: vscode.Uri[] | vscode.Uri, selectedUris?: vscode.Uri[]): Promise<ScanSelectedFilesCommandResult> => {
            const allowed = await ensureScanAllowedForSession();
            if (!allowed) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }
            const normalizedRequested = Array.isArray(selectedUris) && selectedUris.length
                ? selectedUris
                : Array.isArray(requestedUris)
                    ? requestedUris
                    : requestedUris
                        ? [requestedUris]
                        : undefined;
            const fileUris = normalizedRequested?.length ? normalizedRequested : await pickScanFiles();
            if (!fileUris?.length) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            statusBar.showScanning();
            diagnostics.clear();
            sidebar.clear();
            const scanStartedAt = Date.now();
            emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_started', {
                scope: 'selected_files',
                startedAt: scanStartedAt,
                fileCount: fileUris.length,
                status: 'started',
            });

            try {
                const summary = await scanSelectedFiles({
                    files: fileUris,
                    scanEngine,
                    diagnostics,
                    skipConfirmation: true,
                });
                const enrichedResults = await annotateProviderComparisonNotes(
                    await finalizeMultiFileResults(summary.results, `Selected files: ${fileUris.length} file(s)`),
                );
                const totalFindings = enrichedResults.reduce((total, item) => total + item.result.findings.length, 0);
                for (const item of enrichedResults) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                }
                await persistScans();

                if (enrichedResults.length) {
                    const topResult = enrichedResults
                        .slice()
                        .sort((left, right) => right.result.score - left.result.score)[0];
                    sidebar.refresh(topResult.result);
                    statusBar.showResult(topResult.result);
                    chatView.setLastScanTarget(`Selected files: ${enrichedResults.length} file(s)`);
                    sessionScanCount += 1;
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'scan_run', {
                        scope: 'selected_files',
                        file_count: enrichedResults.length,
                        finding_count: totalFindings,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    if (sessionScanCount === 2) {
                        void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'second_scan', { scope: 'selected_files' }, {
                            registry,
                            includeProviderModel: true,
                            includeProject: true,
                        });
                    }
                    void maybePromptUsefulnessFeedback(allowed, {
                        scope: 'selected_files',
                        file_count: enrichedResults.length,
                        finding_count: totalFindings,
                    });
                } else {
                    refreshIdleStatus();
                }
                if (summary.status === 'failed') {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                        scope: 'selected_files',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: totalFindings,
                        status: 'failed',
                        stage: 'file_scan',
                        errorKind: 'provider_error',
                    });
                } else {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_completed', {
                        scope: 'selected_files',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: totalFindings,
                        status: 'completed',
                    });
                }

                if (summary.status === 'completed' && enrichedResults.length) {
                    await persistLastReportSnapshot({
                        targetLabel: `${enrichedResults.length} selected file(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(enrichedResults[0].uri.fsPath)),
                        errors: summary.errors,
                        results: enrichedResults,
                    });
                    vscode.window.showInformationMessage(
                        `${PROFILE.displayLabel}: Scanned ${enrichedResults.length} selected file(s) with ${totalFindings} finding(s)${summary.errors.length ? ` (${summary.errors.length} error(s))` : ''}`
                    );
                } else if (summary.status === 'failed') {
                    vscode.window.showErrorMessage(
                        `${PROFILE.displayLabel}: Selected-files scan failed for all ${fileUris.length} file(s). ${summary.errors.length} error(s) were captured.`
                    );
                } else if (summary.status === 'empty') {
                    vscode.window.showInformationMessage(`${PROFILE.displayLabel}: No supported source files were selected.`);
                }

                return {
                    status: summary.status,
                    files: fileUris,
                    completed: summary.completed,
                    totalFindings,
                    errors: summary.errors,
                    results: enrichedResults,
                };
            } catch (error: any) {
                emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                    scope: 'selected_files',
                    startedAt: scanStartedAt,
                    fileCount: fileUris.length,
                    status: 'failed',
                    stage: 'provider_call',
                    errorKind: classifyTelemetryError(error),
                });
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} selected-files scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanChangedFiles, async (requestedRoot?: vscode.Uri): Promise<ScanChangedFilesCommandResult> => {
            const allowed = await ensureScanAllowedForSession();
            if (!allowed) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }
            const root = requestedRoot ?? await ensureProjectRootReady('Select the repo root Owlvex should use to find changed files.');
            if (!root) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            const fileUris = await collectChangedScannableFiles(root);
            if (!fileUris.length) {
                vscode.window.showInformationMessage(`${PROFILE.displayLabel}: No changed source files were found under ${vscode.workspace.asRelativePath(root, false) || root.fsPath}.`);
                return { status: 'empty', root, files: [], completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            statusBar.showScanning();
            diagnostics.clear();
            sidebar.clear();
            const scanStartedAt = Date.now();
            emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_started', {
                scope: 'changed_files',
                startedAt: scanStartedAt,
                fileCount: fileUris.length,
                status: 'started',
            });

            try {
                const summary = await scanSelectedFiles({
                    files: fileUris,
                    scanEngine,
                    diagnostics,
                    skipConfirmation: true,
                });
                const enrichedResults = await annotateProviderComparisonNotes(
                    await finalizeMultiFileResults(summary.results, `Changed files: ${fileUris.length} file(s)`),
                );
                const totalFindings = enrichedResults.reduce((total, item) => total + item.result.findings.length, 0);
                for (const item of enrichedResults) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                }
                await persistScans();

                if (enrichedResults.length) {
                    const topResult = enrichedResults
                        .slice()
                        .sort((left, right) => right.result.score - left.result.score)[0];
                    sidebar.refresh(topResult.result);
                    statusBar.showResult(topResult.result);
                    chatView.setLastScanTarget(`Changed files: ${enrichedResults.length} file(s)`);
                    sessionScanCount += 1;
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'scan_run', {
                        scope: 'changed_files',
                        file_count: enrichedResults.length,
                        finding_count: totalFindings,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    if (sessionScanCount === 2) {
                        void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'second_scan', { scope: 'changed_files' }, {
                            registry,
                            includeProviderModel: true,
                            includeProject: true,
                        });
                    }
                    void maybePromptUsefulnessFeedback(allowed, {
                        scope: 'changed_files',
                        file_count: enrichedResults.length,
                        finding_count: totalFindings,
                    });
                    await persistLastReportSnapshot({
                        targetLabel: `${enrichedResults.length} changed file(s)`,
                        outputRoot: root,
                        errors: summary.errors,
                        results: enrichedResults,
                    });
                } else {
                    refreshIdleStatus();
                }
                if (summary.status === 'failed') {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                        scope: 'changed_files',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: totalFindings,
                        status: 'failed',
                        stage: 'file_scan',
                        errorKind: 'provider_error',
                    });
                } else {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_completed', {
                        scope: 'changed_files',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: totalFindings,
                        status: 'completed',
                    });
                }

                if (summary.status === 'completed' && enrichedResults.length) {
                    vscode.window.showInformationMessage(
                        `${PROFILE.displayLabel}: Scanned ${enrichedResults.length} changed file(s) with ${totalFindings} finding(s)${summary.errors.length ? ` (${summary.errors.length} error(s))` : ''}`
                    );
                } else if (summary.status === 'failed') {
                    vscode.window.showErrorMessage(
                        `${PROFILE.displayLabel}: Changed-files scan failed for all ${fileUris.length} file(s). ${summary.errors.length} error(s) were captured.`
                    );
                }

                return {
                    status: summary.status,
                    root,
                    files: fileUris,
                    completed: summary.completed,
                    totalFindings,
                    errors: summary.errors,
                    results: enrichedResults,
                };
            } catch (error: any) {
                emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                    scope: 'changed_files',
                    startedAt: scanStartedAt,
                    fileCount: fileUris.length,
                    status: 'failed',
                    stage: 'provider_call',
                    errorKind: classifyTelemetryError(error),
                });
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} changed-files scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanOpenEditors, async (): Promise<ScanOpenEditorsCommandResult> => {
            const allowed = await ensureScanAllowedForSession();
            if (!allowed) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }
            const fileUris = collectOpenEditorUris();
            if (!fileUris.length) {
                vscode.window.showInformationMessage(`${PROFILE.displayLabel}: No supported open editors were available to scan.`);
                return { status: 'empty', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            statusBar.showScanning();
            diagnostics.clear();
            sidebar.clear();
            const scanStartedAt = Date.now();
            emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_started', {
                scope: 'open_editors',
                startedAt: scanStartedAt,
                fileCount: fileUris.length,
                status: 'started',
            });

            try {
                const summary = await scanSelectedFiles({
                    files: fileUris,
                    scanEngine,
                    diagnostics,
                    skipConfirmation: true,
                });
                const enrichedResults = await annotateProviderComparisonNotes(
                    await finalizeMultiFileResults(summary.results, `Open editors: ${fileUris.length} file(s)`),
                );
                const totalFindings = enrichedResults.reduce((total, item) => total + item.result.findings.length, 0);
                for (const item of enrichedResults) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                }
                await persistScans();

                if (enrichedResults.length) {
                    const topResult = enrichedResults
                        .slice()
                        .sort((left, right) => right.result.score - left.result.score)[0];
                    sidebar.refresh(topResult.result);
                    statusBar.showResult(topResult.result);
                    chatView.setLastScanTarget(`Open editors: ${enrichedResults.length} file(s)`);
                    sessionScanCount += 1;
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'scan_run', {
                        scope: 'open_editors',
                        file_count: enrichedResults.length,
                        finding_count: totalFindings,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    if (sessionScanCount === 2) {
                        void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'second_scan', { scope: 'open_editors' }, {
                            registry,
                            includeProviderModel: true,
                            includeProject: true,
                        });
                    }
                    void maybePromptUsefulnessFeedback(allowed, {
                        scope: 'open_editors',
                        file_count: enrichedResults.length,
                        finding_count: totalFindings,
                    });
                    await persistLastReportSnapshot({
                        targetLabel: `${enrichedResults.length} open editor(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(enrichedResults[0].uri.fsPath)),
                        errors: summary.errors,
                        results: enrichedResults,
                    });
                } else {
                    refreshIdleStatus();
                }
                if (summary.status === 'failed') {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                        scope: 'open_editors',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: totalFindings,
                        status: 'failed',
                        stage: 'file_scan',
                        errorKind: 'provider_error',
                    });
                } else {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_completed', {
                        scope: 'open_editors',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: totalFindings,
                        status: 'completed',
                    });
                }

                if (summary.status === 'completed' && enrichedResults.length) {
                    vscode.window.showInformationMessage(
                        `${PROFILE.displayLabel}: Scanned ${enrichedResults.length} open editor(s) with ${totalFindings} finding(s)${summary.errors.length ? ` (${summary.errors.length} error(s))` : ''}`
                    );
                }

                return {
                    status: summary.status,
                    files: fileUris,
                    completed: summary.completed,
                    totalFindings,
                    errors: summary.errors,
                    results: enrichedResults,
                };
            } catch (error: any) {
                emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                    scope: 'open_editors',
                    startedAt: scanStartedAt,
                    fileCount: fileUris.length,
                    status: 'failed',
                    stage: 'provider_call',
                    errorKind: classifyTelemetryError(error),
                });
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} open-editors scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc: vscode.TextDocument) => {
            const cfg = vscode.workspace.getConfiguration(PROFILE.configSection);
            if (!cfg.get<boolean>('scanOnSave', false)) return;

            statusBar.showScanning();
            try {
                const [annotated] = await annotateProviderComparisonNotes([{
                    uri: doc.uri,
                    result: applyRulePackContext(await scanEngine.scanDocument(doc)),
                }]);
                const result = annotated.result;
                storeScanResult(result.scanId, result, vscode.workspace.asRelativePath(doc.uri, false));
                await persistScans();
                await persistLastReportSnapshot({
                    targetLabel: vscode.workspace.asRelativePath(doc.uri, false),
                    outputRoot: vscode.Uri.file(path.dirname(doc.uri.fsPath)),
                    errors: [],
                    results: [{ uri: doc.uri, result }],
                });
                diagnostics.applyFindings(doc, result.findings);
                sidebar.refresh(result);
                statusBar.showResult(result);
                chatView.setLastScanTarget(`Saved file: ${vscode.workspace.asRelativePath(doc.uri, false)}`);
            } catch (error: any) {
                statusBar.showError(error.message);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.switchModel, async () => {
            const provider = registry.getActive();
            const previousModel = provider.selectedModel;
            const models = await provider.listModels();
            const picked = await vscode.window.showQuickPick(models, {
                placeHolder: `Select model (current: ${provider.selectedModel})`,
            });

            if (picked) {
                await registry.setProviderModel(provider.id, picked);
                void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'llm_model_selected', {
                    previous_model: previousModel,
                }, {
                    registry,
                    includeProviderModel: true,
                    includeProject: true,
                });
                vscode.window.showInformationMessage(`${PROFILE.displayLabel}: Model switched to ${picked}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.configureProviderThrottling, async () => {
            await configureProviderThrottlingForActiveProvider(registry);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.setupAI, async () => {
            const currentProvider = registry.getActive();
            const providerChoice = await vscode.window.showQuickPick(
                registry.allProviders().map(item => ({
                    label: item.name,
                    description: item.id === currentProvider.id ? 'Current provider' : '',
                    providerId: item.id,
                })),
                {
                    placeHolder: 'Choose the LLM provider to configure',
                    ignoreFocusOut: true,
                },
            );
            if (!providerChoice) {
                return;
            }

            const provider = registry.getProvider(providerChoice.providerId);
            if (!provider) {
                vscode.window.showErrorMessage(`${PROFILE.displayLabel}: Unknown provider "${providerChoice.providerId}".`);
                return;
            }

            if (provider.id === 'ollama') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const host = await promptForSetting(
                    'ollama.host',
                    'Enter the Ollama host URL',
                    'http://localhost:11434',
                    (value) => value.trim() ? undefined : 'The Ollama host is required.',
                );
                if (!host) {
                    return;
                }

                const model = await vscode.window.showInputBox({
                    prompt: 'Enter the Ollama model name',
                    placeHolder: 'For example: qwen2.5:7b',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The Ollama model name is required.',
                });
                if (!model) {
                    return;
                }

                await registry.setProviderModel(provider.id, model.trim());
                const { success, latencyMs } = await provider.testConnection();
                if (success) {
                    await registry.setActiveProvider(provider.id);
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'llm_provider_selected', {
                        previous_provider: currentProvider.id,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'llm_connection_configured', {
                        connection_result: 'success',
                        latency_ms: latencyMs,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    vscode.window.showInformationMessage(`Ollama connected (${latencyMs}ms) using ${provider.selectedModel} at ${host}`);
                } else {
                    vscode.window.showErrorMessage('Ollama connection failed. Check the host URL, confirm Ollama is running, and verify the model is installed.');
                }
                return;
            }

            if (provider.id === 'azure-foundry') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const endpoint = await promptForSetting(
                    'foundry.endpoint',
                    'Enter the Azure AI Foundry endpoint for this environment',
                    'https://your-resource.openai.azure.com',
                    (value) => {
                        if (!value.trim()) return 'The Foundry endpoint is required.';
                        return isLikelyAzureFoundryEndpoint(value)
                            ? undefined
                            : 'Use the Azure endpoint from Keys and Endpoint, for example https://your-resource.openai.azure.com';
                    },
                );
                if (!endpoint) {
                    return;
                }

                const deployment = await vscode.window.showInputBox({
                    prompt: 'Enter the Azure AI Foundry deployment name',
                    placeHolder: 'Use the deployment name you created in Azure AI Foundry, for example: security-chat-prod',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The deployment name is required.',
                });
                if (!deployment) {
                    return;
                }

                const trimmedDeployment = deployment.trim();
                await persistProviderConnectionSetting('foundry.model', trimmedDeployment);
                const existingDeployments = vscode.workspace
                    .getConfiguration(PROFILE.configSection)
                    .get<string[]>('foundry.deployments', []);
                const nextDeployments = [...new Set([trimmedDeployment, ...existingDeployments.map(item => item.trim()).filter(Boolean)])];
                await persistProviderConnectionSetting('foundry.deployments', nextDeployments as any);
            }

            if (provider.id === 'anthropic') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const model = await vscode.window.showInputBox({
                    prompt: 'Enter the Anthropic model name',
                    placeHolder: 'For example: claude-sonnet-4-6',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The model name is required.',
                });
                if (!model) {
                    return;
                }

                await registry.setProviderModel(provider.id, model.trim());
            }

            if (provider.id === 'openai' || provider.id === 'gemini' || provider.id === 'mistral' || provider.id === 'groq') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const model = await vscode.window.showInputBox({
                    prompt: `Enter the ${provider.name} model name`,
                    placeHolder: `For example: ${provider.selectedModel}`,
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The model name is required.',
                });
                if (!model) {
                    return;
                }

                await registry.setProviderModel(provider.id, model.trim());
            }

            if (provider.id === 'custom') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const baseUrl = await promptForSetting(
                    'custom.baseUrl',
                    'Enter the base URL for your OpenAI-compatible endpoint',
                    'https://api.example.com',
                    (value) => value.trim() ? undefined : 'The custom endpoint URL is required.',
                );
                if (!baseUrl) {
                    return;
                }

                const model = await vscode.window.showInputBox({
                    prompt: 'Enter the model name for the custom endpoint',
                    placeHolder: 'For example: my-custom-model',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The custom model name is required.',
                });
                if (!model) {
                    return;
                }

                await persistProviderConnectionSetting('custom.model', model.trim());
            }

            let key: string | undefined;
            if (provider.id !== 'ollama') {
                const secretName = getProviderApiKeySecretName(provider.id);
                const existingKey = await context.secrets.get(secretName);
                key = await vscode.window.showInputBox({
                    prompt: providerAllowsOptionalApiKey(provider.id)
                        ? existingKey
                            ? `Enter API key for ${provider.name} to replace the saved key, or leave blank to keep it`
                            : `Enter API key for ${provider.name} (leave blank if this endpoint does not require auth)`
                        : existingKey
                            ? `Enter API key for ${provider.name} to replace the saved key, or leave blank to keep it`
                            : `Enter API key for ${provider.name}`,
                    placeHolder: existingKey
                        ? 'Leave blank to keep the saved key'
                        : undefined,
                    ignoreFocusOut: true,
                    password: true,
                });

                const apiKeyResolution = resolveProviderApiKeyInput(key, {
                    hasExistingKey: Boolean(existingKey),
                    allowBlank: providerAllowsOptionalApiKey(provider.id),
                });

                if (apiKeyResolution.action === 'cancel') {
                    return;
                }

                if (apiKeyResolution.action === 'invalid') {
                    return;
                }

                if (apiKeyResolution.action === 'store') {
                    await context.secrets.store(secretName, apiKeyResolution.key);
                } else if (apiKeyResolution.action === 'delete') {
                    await context.secrets.delete(secretName);
                }
            }

            const { success, latencyMs, message } = await provider.testConnection();
            if (success) {
                try {
                    const models = await provider.listModels();
                    const activeModel = resolveConnectedModelSelection(provider.selectedModel, models);
                    if (activeModel && activeModel !== provider.selectedModel) {
                        await registry.setProviderModel(provider.id, activeModel);
                    }
                    await registry.setActiveProvider(provider.id);
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'llm_provider_selected', {
                        previous_provider: currentProvider.id,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'llm_connection_configured', {
                        connection_result: 'success',
                        latency_ms: latencyMs,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    await promptOnboardingChoices(
                        `${provider.name} connected (${latencyMs}ms) using ${activeModel}`,
                        buildProviderConnectedChoices(),
                    );
                } catch {
                    await registry.setActiveProvider(provider.id);
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'llm_provider_selected', {
                        previous_provider: currentProvider.id,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'llm_connection_configured', {
                        connection_result: 'success',
                        latency_ms: latencyMs,
                    }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                    await promptOnboardingChoices(
                        `${provider.name} connected (${latencyMs}ms)`,
                        buildProviderConnectedChoices(),
                    );
                }
            } else {
                const extraHint = provider.id === 'azure-foundry'
                    ? ' Check the endpoint, deployment name, and API key.'
                    : provider.id === 'custom'
                        ? ' Check the base URL, model name, and API key.'
                        : ' Check your key.';
                vscode.window.showErrorMessage(message?.trim() || `${provider.name} connection failed.${extraHint}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.removeAIConnection, async () => {
            const currentProvider = registry.getActive();
            const providerChoice = await vscode.window.showQuickPick(
                registry.allProviders().map(item => ({
                    label: item.name,
                    description: item.id === currentProvider.id ? 'Current provider' : '',
                    providerId: item.id,
                })),
                {
                    placeHolder: 'Choose the provider connection to remove',
                    ignoreFocusOut: true,
                },
            );
            if (!providerChoice) {
                return;
            }

            const confirmation = await vscode.window.showWarningMessage(
                `Remove the saved ${providerChoice.label} connection from this VS Code profile?`,
                { modal: true },
                'Remove',
            );
            if (confirmation !== 'Remove') {
                return;
            }

            await clearProviderConnection(providerChoice.providerId, context.secrets);
            if (registry.getActive().id === providerChoice.providerId) {
                await registry.setActiveProvider(await chooseFallbackProviderId(registry, providerChoice.providerId));
            }

            vscode.window.showInformationMessage(`${PROFILE.displayLabel}: Removed saved ${providerChoice.label} connection.`);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.openProjectContext, async () => {
            const result = await openOrCreateProjectContext();
            if (result.relativePath) {
                vscode.window.showInformationMessage(
                    result.created
                        ? `${PROFILE.displayLabel}: Created project context at ${result.relativePath}`
                        : `${PROFILE.displayLabel}: Opened project context at ${result.relativePath}`,
                );
            } else {
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: Opened an untitled project context document. Save it into the repo to reuse it automatically.`,
                );
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.openDesignContext, async () => {
            const result = await openOrCreateDesignContext();
            if (result.relativePath) {
                vscode.window.showInformationMessage(
                    result.created
                        ? `${PROFILE.displayLabel}: Created design context at ${result.relativePath}`
                        : `${PROFILE.displayLabel}: Opened design context at ${result.relativePath}`,
                );
            } else {
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: Opened an untitled design context document. Save it inside .owlvex/design to reuse it in scans.`,
                );
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.openDriftBox, async () => {
            const result = await openOrCreateDriftBox();
            if (result.relativePath) {
                vscode.window.showInformationMessage(
                    result.created
                        ? `${PROFILE.displayLabel}: Created drift box at ${result.relativePath}`
                        : `${PROFILE.displayLabel}: Opened drift box at ${result.relativePath}`,
                );
            } else {
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: Opened an untitled drift configuration. Save it inside .owlvex/drift before using it in scans.`,
                );
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.testAI, async () => {
            const { success, latencyMs, message, providerName, model } = await testCurrentProviderConnection(registry);
            if (success) {
                vscode.window.showInformationMessage(`${providerName} is reachable (${latencyMs}ms) using ${model}`);
            } else {
                vscode.window.showErrorMessage(message?.trim() || `${providerName} connection failed. ${getProviderSetupSummary(registry.getActive().id)}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.testTrialSetup, async () => {
            const currentApiUrl = getConfiguredApiUrl();
            const backend = await testBackendConnection(currentApiUrl);
            const licenceKey = await licenceMgr.getKey();
            let licenceSummary = 'No licence key entered yet.';
            let licenceValid = false;

            if (licenceKey && backend.success) {
                try {
                    const info = await licenceMgr.validate(currentApiUrl);
                    licenceSummary = `Licence valid: ${buildLicenceStatusSummary(info)}`;
                    licenceValid = true;
                    refreshIdleStatus();
                    void refreshRulePackRuntime();
                } catch (error: any) {
                    licenceSummary = `Licence validation failed: ${error.message}`;
                    if (isRevocationLikeError(error)) {
                        licenceMgr.clearCachedInfo();
                        await purgeRulePackState();
                        statusBar.showUnlicensed();
                    }
                }
            } else if (licenceKey) {
                licenceSummary = 'Licence key stored, but backend is not reachable yet.';
            }

            const provider = registry.getActive();
            const providerConfigured = await provider.isConfigured().catch(() => false);
            let providerSummary = `${provider.name} is not configured yet.`;
            let providerReady = false;

            if (providerConfigured) {
                const providerCheck = await provider.testConnection();
                if (providerCheck.success) {
                    providerSummary = `${provider.name} reachable (${providerCheck.latencyMs}ms) using ${provider.selectedModel}`;
                    providerReady = true;
                } else {
                    providerSummary = providerCheck.message?.trim()
                        || `${provider.name} is configured but the connection test failed.`;
                }
            }

            const lines = [
                `Backend: ${backend.success ? `reachable (${backend.latencyMs}ms)` : backend.message ?? 'unreachable'}`,
                `Backend URL: ${currentApiUrl}`,
                `Licence: ${licenceSummary}`,
                `LLM: ${providerSummary}`,
            ];

            if (licenceValid) {
                const info = licenceMgr.getCachedInfo();
                if (info) {
                    lines.push(...buildPlanNextStepGuidance(info));
                }
            }

            if (backend.success && licenceValid && providerReady) {
                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: Trial setup is ready.\n${lines.join('\n')}`,
                );
                return {
                    status: 'ready',
                    backend: true,
                    licence: true,
                    provider: true,
                    summary: lines,
                };
            }

            vscode.window.showWarningMessage(
                `${PROFILE.displayLabel}: Trial setup still needs attention.\n${lines.join('\n')}`,
            );
            return {
                status: 'needs_attention',
                backend: backend.success,
                licence: licenceValid,
                provider: providerReady,
                summary: lines,
            };
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanWorkspace, async (requestedRoot?: vscode.Uri): Promise<ScanWorkspaceCommandResult> => {
            const allowed = await ensureScanAllowedForSession();
            if (!allowed) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }
            const root = requestedRoot ?? await ensureProjectRootReady('Select the repo root Owlvex should treat as this project before scanning the workspace.');
            if (!root) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            const scanStartedAt = Date.now();
            emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_started', {
                scope: 'workspace',
                startedAt: scanStartedAt,
                status: 'started',
            });

            try {
                const summary = await scanFolder({
                    root,
                    scanEngine,
                    diagnostics,
                    skipConfirmation: true,
                });
                summary.results = await annotateProviderComparisonNotes(
                    await finalizeMultiFileResults(
                        summary.results,
                        `Folder: ${vscode.workspace.asRelativePath(root, false) || root.fsPath}`,
                    ),
                );

                for (const item of summary.results) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                }
                await persistScans();
                await persistLastReportSnapshot({
                    targetLabel: vscode.workspace.asRelativePath(root, false) || root.fsPath,
                    outputRoot: root,
                    errors: summary.errors,
                    results: summary.results,
                });
                chatView.setLastScanTarget(`Folder: ${vscode.workspace.asRelativePath(root, false) || root.fsPath}`);
                sessionScanCount += 1;
                void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'scan_run', {
                    scope: 'workspace',
                    file_count: summary.completed,
                    finding_count: summary.totalFindings,
                }, {
                    registry,
                    includeProviderModel: true,
                    includeProject: true,
                });
                if (summary.status === 'failed') {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                        scope: 'workspace',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: summary.totalFindings,
                        status: 'failed',
                        stage: 'file_scan',
                        errorKind: 'provider_error',
                    });
                } else {
                    emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_completed', {
                        scope: 'workspace',
                        startedAt: scanStartedAt,
                        fileCount: summary.completed,
                        findingCount: summary.totalFindings,
                        status: 'completed',
                    });
                }
                if (sessionScanCount === 2) {
                    void trackUsageEvent(licenceMgr, getConfiguredApiUrl, 'second_scan', { scope: 'workspace' }, {
                        registry,
                        includeProviderModel: true,
                        includeProject: true,
                    });
                }
                void maybePromptUsefulnessFeedback(allowed, {
                    scope: 'workspace',
                    file_count: summary.completed,
                    finding_count: summary.totalFindings,
                });

                const msg = `${PROFILE.displayLabel}: Scanned ${summary.completed} file(s) in ${root.fsPath} - ${summary.totalFindings} finding(s)`;
                if (summary.errors.length) {
                    vscode.window.showWarningMessage(`${msg} (${summary.errors.length} error(s) - see output)`);
                } else if (summary.completed > 0) {
                    vscode.window.showInformationMessage(msg);
                }

                return { root, ...summary };
            } catch (error: any) {
                emitDevScanLifecycleEvent(licenceMgr, getConfiguredApiUrl, registry, 'scan_failed', {
                    scope: 'workspace',
                    startedAt: scanStartedAt,
                    status: 'failed',
                    stage: 'provider_call',
                    errorKind: classifyTelemetryError(error),
                });
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanWorkspaceReport, async (commandOptions?: ReportCommandOptions): Promise<ReportCommandResult> => {
            const allowed = await ensureScanAllowedForSession();
            if (!allowed) {
                return { status: 'cancelled' };
            }
            try {
                let reportVariant: ReportVariant | undefined = commandOptions?.reportVariant;
                if (reportVariant !== 'summary' && reportVariant !== 'full') {
                    const pickedReportVariant = await vscode.window.showQuickPick([
                        {
                            label: 'Summary Report',
                            description: 'Developer view: what to fix first',
                            reportVariant: 'summary' as ReportVariant,
                        },
                        {
                            label: 'Full Evidence Report',
                            description: 'Complete evidence, scoring, mappings, and AI review detail',
                            reportVariant: 'full' as ReportVariant,
                        },
                    ], {
                        placeHolder: 'Choose report type',
                    });
                    if (!pickedReportVariant) return { status: 'cancelled' };
                    reportVariant = pickedReportVariant.reportVariant;
                }

                const lastSnapshot = restoreLastReportSnapshot();
                const options: vscode.QuickPickItem[] = [];
                if (lastSnapshot) {
                    options.push({
                        label: 'Use last scan',
                        description: lastSnapshot.targetLabel,
                    });
                }
                options.push(
                    { label: 'Scan selected file and create report', description: 'Pick a file, scan it, then create a report' },
                    { label: 'Scan selected files and create report', description: 'Pick multiple files, scan them, then create a report' },
                    { label: 'Scan open editors and create report', description: 'Scan currently open editors, then create a report' },
                    { label: 'Scan selected folder and create report', description: 'Pick a folder, scan it, then create a report' },
                );

                const picked = await vscode.window.showQuickPick(options, {
                    placeHolder: 'Choose how to create the report',
                });
                if (!picked) return { status: 'cancelled' };

                if (picked.label === 'Use last scan' && lastSnapshot) {
                    chatView.setLastScanTarget(`Report from last scan: ${lastSnapshot.targetLabel}`);
                    return {
                        status: 'completed',
                        ...(await createAndOpenReport(lastSnapshot, reportVariant)),
                    };
                }

                if (picked.label === 'Scan selected file and create report') {
                    const fileUri = await resolveScanFileTarget();
                    if (!fileUri) return { status: 'cancelled' };

                    const document = await vscode.workspace.openTextDocument(fileUri);
                    await vscode.window.showTextDocument(document, { preview: false });

                    statusBar.showScanning();
                    diagnostics.clear(document.uri);
                    sidebar.clear();

                    const [annotated] = await annotateProviderComparisonNotes([{
                        uri: document.uri,
                        result: applyRulePackContext(await scanEngine.scanDocument(document)),
                    }]);
                    const result = annotated.result;
                    storeScanResult(result.scanId, result, vscode.workspace.asRelativePath(document.uri, false));
                    await persistScans();
                    diagnostics.applyFindings(document, result.findings);
                    sidebar.refresh(result);
                    statusBar.showResult(result);

                    const snapshot: ReportSnapshot = {
                        targetLabel: vscode.workspace.asRelativePath(document.uri, false),
                        outputRoot: vscode.Uri.file(path.dirname(document.uri.fsPath)),
                        errors: [],
                        results: [{ uri: document.uri, result }],
                    };
                    await persistLastReportSnapshot(snapshot);
                    chatView.setLastScanTarget(`Report file: ${snapshot.targetLabel}`);
                    return {
                        status: 'completed',
                        ...(await createAndOpenReport(snapshot, reportVariant)),
                    };
                }

                if (picked.label === 'Scan selected files and create report') {
                    const fileUris = await pickScanFiles();
                    if (!fileUris?.length) return { status: 'cancelled' };

                    statusBar.showScanning();
                    diagnostics.clear();
                    sidebar.clear();

                    const summary = await scanSelectedFiles({
                        files: fileUris,
                        scanEngine,
                        diagnostics,
                        skipConfirmation: true,
                    });
                    summary.results = await annotateProviderComparisonNotes(
                        await finalizeMultiFileResults(summary.results, `Report selected files: ${fileUris.length} file(s)`),
                    );

                    for (const item of summary.results) {
                        storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                    }
                    await persistScans();

                    if (!summary.completed) {
                        refreshIdleStatus();
                        return {
                            status: summary.status,
                            summary: {
                                completed: summary.completed,
                                totalFindings: summary.totalFindings,
                                errors: summary.errors,
                                results: summary.results,
                            },
                        };
                    }

                    const snapshot: ReportSnapshot = {
                        targetLabel: `${summary.completed} selected file(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(summary.results[0].uri.fsPath)),
                        errors: summary.errors,
                        results: summary.results,
                    };
                    await persistLastReportSnapshot(snapshot);
                    chatView.setLastScanTarget(`Report selected files: ${summary.completed} file(s)`);
                    return {
                        status: 'completed',
                        ...(await createAndOpenReport(snapshot, reportVariant)),
                    };
                }

                if (picked.label === 'Scan open editors and create report') {
                    const fileUris = collectOpenEditorUris();
                    if (!fileUris.length) {
                        return { status: 'empty' };
                    }

                    statusBar.showScanning();
                    diagnostics.clear();
                    sidebar.clear();

                    const summary = await scanSelectedFiles({
                        files: fileUris,
                        scanEngine,
                        diagnostics,
                        skipConfirmation: true,
                    });
                    summary.results = await annotateProviderComparisonNotes(
                        await finalizeMultiFileResults(summary.results, `Report open editors: ${fileUris.length} file(s)`),
                    );

                    for (const item of summary.results) {
                        storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                    }
                    await persistScans();

                    if (!summary.completed) {
                        refreshIdleStatus();
                        return {
                            status: summary.status,
                            summary: {
                                completed: summary.completed,
                                totalFindings: summary.totalFindings,
                                errors: summary.errors,
                                results: summary.results,
                            },
                        };
                    }

                    const snapshot: ReportSnapshot = {
                        targetLabel: `${summary.completed} open editor(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(summary.results[0].uri.fsPath)),
                        errors: summary.errors,
                        results: summary.results,
                    };
                    await persistLastReportSnapshot(snapshot);
                    chatView.setLastScanTarget(`Report open editors: ${summary.completed} file(s)`);
                    return {
                        status: 'completed',
                        ...(await createAndOpenReport(snapshot, reportVariant)),
                    };
                }

                const root = await ensureProjectRootReady('Select the repo root Owlvex should use when generating a workspace report.');
                if (!root) return { status: 'cancelled' };

                statusBar.showScanning();
                const summary = await scanFolder({
                    root,
                    scanEngine,
                    diagnostics,
                    skipConfirmation: true,
                });
                summary.results = await annotateProviderComparisonNotes(
                    await finalizeMultiFileResults(
                        summary.results,
                        `Report folder: ${vscode.workspace.asRelativePath(root, false) || root.fsPath}`,
                    ),
                );

                for (const item of summary.results) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                }
                await persistScans();

                if (!summary.completed) {
                    refreshIdleStatus();
                    return {
                        status: summary.status,
                        summary: {
                            completed: summary.completed,
                            totalFindings: summary.totalFindings,
                            errors: summary.errors,
                            results: summary.results,
                        },
                    };
                }

                const snapshot: ReportSnapshot = {
                    targetLabel: vscode.workspace.asRelativePath(root, false) || root.fsPath,
                    outputRoot: root,
                    errors: summary.errors,
                    results: summary.results,
                };
                await persistLastReportSnapshot(snapshot);
                chatView.setLastScanTarget(`Report folder: ${snapshot.targetLabel}`);
                return {
                    status: 'completed',
                    ...(await createAndOpenReport(snapshot, reportVariant)),
                };
            } catch (error: any) {
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} report failed: ${error.message}`);
                return { status: 'cancelled' };
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.openPromptEditor, async () => {
            const licenceInfo = await resolveLicenceInfoForAccess(licenceMgr, getConfiguredApiUrl);
            if (!hasPromptEditorAccess(licenceInfo)) {
                vscode.window.showInformationMessage(buildPlanUpgradeMessage('prompt-editor'));
                return;
            }
            await chatView.show();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.compareScans, async () => {
            const licenceInfo = await resolveLicenceInfoForAccess(licenceMgr, getConfiguredApiUrl);
            if (!hasComparisonAccess(licenceInfo)) {
                vscode.window.showInformationMessage(buildPlanUpgradeMessage('comparison'));
                return;
            }
            const cfg = vscode.workspace.getConfiguration(PROFILE.configSection);
            const compareApiUrl = cfg.get<string>('apiUrl') ?? PROFILE.defaultApiUrl;
            const licenceKey = await licenceMgr.getKey();
            if (!licenceKey) {
                vscode.window.showErrorMessage('No licence key. Run "Owlvex: Enter Licence Key".');
                return;
            }

            const storedReports = Array.from(reportStore.values());
            if (storedReports.length < 2) {
                vscode.window.showWarningMessage(
                    'Owlvex: Need at least 2 reports to compare. Create two reports first.'
                );
                return;
            }

            const newestFirstReports = [...storedReports].sort((left, right) =>
                new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime(),
            );
            const scanAChoice = await vscode.window.showQuickPick(newestFirstReports.map(buildStoredReportComparisonChoice), {
                placeHolder: 'Select first report to compare. Owlvex will order reports by generation time.',
            });
            if (!scanAChoice) return;

            const scanBChoice = await vscode.window.showQuickPick(
                newestFirstReports
                    .filter(item => item.reportId !== scanAChoice.record.reportId)
                    .map(buildStoredReportComparisonChoice),
                { placeHolder: 'Select second report to compare. Earlier becomes Before; later becomes After.' },
            );
            if (!scanBChoice) return;

            try {
                await compareStoredReports(compareApiUrl, licenceKey, scanAChoice.record, scanBChoice.record);
            } catch (error: any) {
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} compare failed: ${error.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.compareLatestReports, async () => {
            const licenceInfo = await resolveLicenceInfoForAccess(licenceMgr, getConfiguredApiUrl);
            if (!hasComparisonAccess(licenceInfo)) {
                vscode.window.showInformationMessage(buildPlanUpgradeMessage('comparison'));
                return;
            }
            const cfg = vscode.workspace.getConfiguration(PROFILE.configSection);
            const compareApiUrl = cfg.get<string>('apiUrl') ?? PROFILE.defaultApiUrl;
            const licenceKey = await licenceMgr.getKey();
            if (!licenceKey) {
                vscode.window.showErrorMessage('No licence key. Run "Owlvex: Enter Licence Key".');
                return;
            }

            const selection = selectLatestTwoReports(Array.from(reportStore.values()));
            if (!selection) {
                vscode.window.showWarningMessage(
                    'Owlvex: Need at least 2 reports to compare. Create two reports first.'
                );
                return;
            }

            try {
                await compareStoredReports(compareApiUrl, licenceKey, selection.baseline, selection.current);
            } catch (error: any) {
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} compare failed: ${error.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.reviewRiskCalibration, async (records?: StoredScanRecord[]) => {
            const scopedScans = Array.isArray(records) && records.length
                ? records.map(item => normalizeStoredScanRecord(item))
                : Array.from(scanStore.values());
            if (!scopedScans.length) {
                vscode.window.showWarningMessage('Owlvex: Run at least one scan before reviewing risk calibration.');
                return { status: 'empty', count: 0 };
            }

            const report = buildRiskCalibrationReport(scopedScans);
            const document = await vscode.workspace.openTextDocument({
                language: 'markdown',
                content: report,
            });
            await vscode.window.showTextDocument(document, { preview: false });
            return { status: 'completed', count: scopedScans.length };
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.revealLine, (line: number) => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;
            const pos = new vscode.Position(Math.max(0, line - 1), 0);
            editor.selection = new vscode.Selection(pos, pos);
            editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        })
    );

    context.subscriptions.push(diagnostics, statusBar);
}

function buildComparisonHtml(diff: any, scoreChange: string): string {
    const normalizedDiff = normalizeComparisonDiff(diff);
    const severityWeight = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 4;
            case 'HIGH': return 3;
            case 'MEDIUM': return 2;
            case 'LOW': return 1;
            default: return 0;
        }
    };

    const canonicalChanges = normalizedDiff.canonical_changes ?? [];
    const weightedBefore = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_a ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedAfter = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_b ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedImprovement = weightedBefore > 0
        ? Math.round(((weightedBefore - weightedAfter) / weightedBefore) * 100)
        : 0;

    const newRows = (normalizedDiff.new_finding_details ?? []).map((f: any) =>
        `<tr class="new"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const resolvedRows = (normalizedDiff.resolved_finding_details ?? []).map((f: any) =>
        `<tr class="resolved"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const canonicalRows = canonicalChanges.map((item: any) => {
        const delta = Number(item.delta ?? 0);
        const deltaLabel = delta > 0 ? `+${delta}` : `${delta}`;
        const deltaClass = delta > 0 ? 'negative' : delta < 0 ? 'positive' : '';
        const issueLabel = item.title || item.issue_id || 'Unresolved finding';
        const issueId = item.issue_id ? `<div class="subtle">${item.issue_id}</div>` : '<div class="subtle">unresolved</div>';
        const frameworks = (item.frameworks ?? []).join(', ') || 'n/a';
        const reduction = (item.count_a ?? 0) > 0
            ? `${Math.round((((item.count_b ?? 0) - (item.count_a ?? 0)) / (item.count_a ?? 0)) * 100)}%`
            : 'n/a';
        return `<tr>
<td><strong>${issueLabel}</strong>${issueId}</td>
<td>${item.severity ?? 'n/a'}</td>
<td>${item.count_a ?? 0}</td>
<td>${item.count_b ?? 0}</td>
<td class="${deltaClass}">${deltaLabel}</td>
<td class="${deltaClass}">${reduction}</td>
<td>${frameworks}</td>
</tr>`;
    }).join('');

    const topImprovements = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) < 0)
        .sort((a: any, b: any) => Number(a.delta ?? 0) - Number(b.delta ?? 0))
        .slice(0, 5)
        .map((item: any) => {
            const before = Number(item.count_a ?? 0);
            const after = Number(item.count_b ?? 0);
            const reduction = before > 0 ? Math.round(((before - after) / before) * 100) : 0;
            return `<li><strong>${item.title || item.issue_id}</strong> <span class="positive">↓ ${reduction}%</span> <span class="subtle">(${before} → ${after})</span></li>`;
        })
        .join('');

    const newRisks = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) > 0)
        .sort((a: any, b: any) => Number(b.delta ?? 0) - Number(a.delta ?? 0))
        .slice(0, 5)
        .map((item: any) =>
            `<li><strong>${item.title || item.issue_id}</strong> <span class="negative">+${item.delta}</span> <span class="subtle">(${item.count_a ?? 0} → ${item.count_b ?? 0})</span></li>`
        )
        .join('');

    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 20px; }
  h1 { font-size: 18px; }
  .summary { display: flex; gap: 24px; margin: 16px 0; }
  .stat { background: var(--vscode-editor-inactiveSelectionBackground); padding: 12px 20px; border-radius: 6px; text-align: center; }
  .stat .value { font-size: 28px; font-weight: bold; }
  .stat .label { font-size: 12px; opacity: 0.7; }
  .positive { color: #4ec9b0; }
  .negative { color: #f48771; }
  .subtle { font-size: 12px; opacity: 0.7; margin-top: 2px; }
  .callouts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 24px 0; }
  .card { background: var(--vscode-editor-inactiveSelectionBackground); padding: 16px; border-radius: 8px; }
  .card h2 { margin-top: 0; font-size: 14px; }
  .card ul { margin: 0; padding-left: 18px; }
  .card li { margin: 8px 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  th { text-align: left; padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 12px; opacity: 0.7; }
  td { padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 13px; vertical-align: top; }
  tr.new td:first-child { color: #f48771; font-weight: bold; }
  tr.resolved td:first-child { color: #4ec9b0; font-weight: bold; }
  h2 { font-size: 14px; margin-top: 24px; }
</style></head><body>
<h1>Report Comparison</h1>
<div class="summary">
  <div class="stat"><div class="value ${Number(scoreChange) >= 0 ? 'positive' : 'negative'}">${scoreChange}</div><div class="label">Score Change</div></div>
  <div class="stat"><div class="value negative">${normalizedDiff.new_findings ?? 0}</div><div class="label">New Findings</div></div>
  <div class="stat"><div class="value positive">${normalizedDiff.resolved_findings ?? 0}</div><div class="label">Resolved</div></div>
</div>
${canonicalRows ? `<h2>Canonical Issue Changes</h2><table><thead><tr><th>Owlvex Issue</th><th>Severity</th><th>Before</th><th>After</th><th>Δ</th><th>Frameworks</th></tr></thead><tbody>${canonicalRows}</tbody></table>` : '<p>No canonical issue changes.</p>'}
${newRows ? `<h2>New Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${newRows}</tbody></table>` : '<p>No new findings.</p>'}
${resolvedRows ? `<h2>Resolved Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${resolvedRows}</tbody></table>` : ''}
</body></html>`;
}

export function normalizeComparisonDiff(diff: any): any {
    const newFindingDetails = Array.isArray(diff?.new_finding_details)
        ? diff.new_finding_details
        : Array.isArray(diff?.new_findings)
            ? diff.new_findings
            : [];
    const resolvedFindingDetails = Array.isArray(diff?.resolved_finding_details)
        ? diff.resolved_finding_details
        : Array.isArray(diff?.resolved_findings)
            ? diff.resolved_findings
            : [];

    return {
        ...diff,
        new_findings: typeof diff?.new_findings === 'number' ? diff.new_findings : newFindingDetails.length,
        resolved_findings: typeof diff?.resolved_findings === 'number' ? diff.resolved_findings : resolvedFindingDetails.length,
        new_finding_details: newFindingDetails,
        resolved_finding_details: resolvedFindingDetails,
    };
}

function buildComparisonHtmlV2(
    diff: any,
    scoreChange: string,
    reports?: { baseline: StoredReportRecord; current: StoredReportRecord; wasReordered: boolean },
): string {
    const normalizedDiff = normalizeComparisonDiff(diff);
    const severityWeight = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 4;
            case 'HIGH': return 3;
            case 'MEDIUM': return 2;
            case 'LOW': return 1;
            default: return 0;
        }
    };

    const canonicalChanges = normalizedDiff.canonical_changes ?? [];
    const weightedBefore = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_a ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedAfter = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_b ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedImprovement = weightedBefore > 0
        ? Math.round(((weightedBefore - weightedAfter) / weightedBefore) * 100)
        : 0;

    const newRows = (normalizedDiff.new_finding_details ?? []).map((f: any) =>
        `<tr class="new"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const resolvedRows = (normalizedDiff.resolved_finding_details ?? []).map((f: any) =>
        `<tr class="resolved"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');

    const canonicalRows = canonicalChanges.map((item: any) => {
        const delta = Number(item.delta ?? 0);
        const deltaLabel = delta > 0 ? `+${delta}` : `${delta}`;
        const deltaClass = delta > 0 ? 'negative' : delta < 0 ? 'positive' : '';
        const issueLabel = item.title || item.issue_id || 'Unresolved finding';
        const issueId = item.issue_id ? `<div class="subtle">${item.issue_id}</div>` : '<div class="subtle">unresolved</div>';
        const frameworks = (item.frameworks ?? []).join(', ') || 'n/a';
        const reduction = (item.count_a ?? 0) > 0
            ? `${Math.round((((item.count_b ?? 0) - (item.count_a ?? 0)) / (item.count_a ?? 0)) * 100)}%`
            : 'n/a';
        return `<tr>
<td><strong>${issueLabel}</strong>${issueId}</td>
<td>${item.severity ?? 'n/a'}</td>
<td>${item.count_a ?? 0}</td>
<td>${item.count_b ?? 0}</td>
<td class="${deltaClass}">${deltaLabel}</td>
<td class="${deltaClass}">${reduction}</td>
<td>${frameworks}</td>
</tr>`;
    }).join('');

    const topImprovements = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) < 0)
        .sort((a: any, b: any) => Number(a.delta ?? 0) - Number(b.delta ?? 0))
        .slice(0, 5)
        .map((item: any) => {
            const before = Number(item.count_a ?? 0);
            const after = Number(item.count_b ?? 0);
            const reduction = before > 0 ? Math.round(((before - after) / before) * 100) : 0;
            return `<li><strong>${item.title || item.issue_id}</strong> <span class="positive">down ${reduction}%</span> <span class="subtle">(${before} -> ${after})</span></li>`;
        })
        .join('');

    const newRisks = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) > 0)
        .sort((a: any, b: any) => Number(b.delta ?? 0) - Number(a.delta ?? 0))
        .slice(0, 5)
        .map((item: any) =>
            `<li><strong>${item.title || item.issue_id}</strong> <span class="negative">+${item.delta}</span> <span class="subtle">(${item.count_a ?? 0} -> ${item.count_b ?? 0})</span></li>`
        )
        .join('');

    const biggestImprovement = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) < 0)
        .sort((a: any, b: any) => Number(a.delta ?? 0) - Number(b.delta ?? 0))[0];
    const biggestRegression = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) > 0)
        .sort((a: any, b: any) => Number(b.delta ?? 0) - Number(a.delta ?? 0))[0];

    const narrativeParts: string[] = [];
    if (biggestImprovement) {
        const before = Number(biggestImprovement.count_a ?? 0);
        const after = Number(biggestImprovement.count_b ?? 0);
        const reduction = before > 0 ? Math.round(((before - after) / before) * 100) : 0;
        narrativeParts.push(
            `The largest improvement was in ${biggestImprovement.title || biggestImprovement.issue_id}, reduced from ${before} to ${after} occurrences (${reduction}% reduction).`
        );
    }
    if (biggestRegression) {
        narrativeParts.push(
            `New risk was introduced in ${biggestRegression.title || biggestRegression.issue_id}, increasing from ${biggestRegression.count_a ?? 0} to ${biggestRegression.count_b ?? 0} occurrences.`
        );
    }
    if (!narrativeParts.length) {
        narrativeParts.push('No major canonical issue movement was detected between these two scans.');
    }
    const numericScoreChange = Number(scoreChange);
    const scoreChangeClass = numericScoreChange > 0 ? 'negative' : numericScoreChange < 0 ? 'positive' : '';
    const baselineLabel = reports
        ? `${reports.baseline.targetLabel || reports.baseline.reportFileName} (${formatStoredScanTimestamp(reports.baseline.createdAt)})`
        : 'Baseline report';
    const currentLabel = reports
        ? `${reports.current.targetLabel || reports.current.reportFileName} (${formatStoredScanTimestamp(reports.current.createdAt)})`
        : 'Current report';
    const orderNotice = reports?.wasReordered
        ? '<div class="notice">Reports were selected out of chronological order. Owlvex compared the earlier report as Before and the later report as After.</div>'
        : '';

    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 24px; max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  .lede { opacity: 0.8; margin-bottom: 20px; }
  .hero { background: linear-gradient(135deg, rgba(78,201,176,0.10), rgba(86,156,214,0.08)); border: 1px solid var(--vscode-panel-border); border-radius: 12px; padding: 18px 20px; margin-bottom: 24px; }
  .hero .eyebrow { text-transform: uppercase; letter-spacing: 0.08em; font-size: 11px; opacity: 0.7; margin-bottom: 6px; }
  .hero .headline { font-size: 30px; font-weight: 700; line-height: 1.1; margin-bottom: 8px; }
  .hero .headline.positive { color: #4ec9b0; }
  .hero .headline.negative { color: #f48771; }
  .hero .support { font-size: 14px; opacity: 0.85; }
  .summary { display: flex; gap: 24px; margin: 16px 0; flex-wrap: wrap; }
  .stat { background: var(--vscode-editor-inactiveSelectionBackground); padding: 12px 20px; border-radius: 6px; text-align: center; min-width: 140px; }
  .stat .value { font-size: 28px; font-weight: bold; }
  .stat .label { font-size: 12px; opacity: 0.7; }
  .positive { color: #4ec9b0; }
  .negative { color: #f48771; }
  .subtle { font-size: 12px; opacity: 0.7; margin-top: 2px; }
  .callouts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 24px 0; }
  .card { background: var(--vscode-editor-inactiveSelectionBackground); padding: 16px; border-radius: 8px; }
  .card h2 { margin-top: 0; font-size: 14px; }
  .card ul { margin: 0; padding-left: 18px; }
  .card li { margin: 8px 0; }
  .legend { opacity: 0.75; font-size: 12px; margin-top: 8px; }
  .timeline { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 16px 0 20px; }
  .timeline-item { background: var(--vscode-editor-inactiveSelectionBackground); border-radius: 6px; padding: 10px 12px; }
  .timeline-label { font-size: 11px; text-transform: uppercase; opacity: 0.7; margin-bottom: 4px; }
  .notice { border: 1px solid var(--vscode-editorWarning-foreground); color: var(--vscode-editorWarning-foreground); border-radius: 6px; padding: 10px 12px; margin: 12px 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  th { text-align: left; padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 12px; opacity: 0.7; }
  td { padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 13px; vertical-align: top; }
  tr.new td:first-child { color: #f48771; font-weight: bold; }
  tr.resolved td:first-child { color: #4ec9b0; font-weight: bold; }
  h2 { font-size: 14px; margin-top: 24px; }
</style></head><body>
<h1>Report Comparison</h1>
  <div class="lede">A canonical before/after view of how security changed between the two reports.</div>
${orderNotice}
<div class="timeline">
  <div class="timeline-item"><div class="timeline-label">Before</div><div>${baselineLabel}</div></div>
  <div class="timeline-item"><div class="timeline-label">After</div><div>${currentLabel}</div></div>
</div>
<div class="hero">
  <div class="eyebrow">Security Posture</div>
  <div class="headline ${weightedAfter <= weightedBefore ? 'positive' : 'negative'}">${weightedAfter <= weightedBefore ? `Improved by ${weightedImprovement}%` : `Regressed by ${Math.abs(weightedImprovement)}%`}</div>
  <div class="support">Weighted exposure moved from ${weightedBefore} to ${weightedAfter}. ${normalizedDiff.resolved_findings ?? 0} findings were resolved and ${normalizedDiff.new_findings ?? 0} new findings were introduced.</div>
</div>
<div class="summary">
  <div class="stat"><div class="value ${scoreChangeClass}">${scoreChange}</div><div class="label">Risk Score Change</div></div>
  <div class="stat"><div class="value negative">${normalizedDiff.new_findings ?? 0}</div><div class="label">New Findings</div></div>
  <div class="stat"><div class="value positive">${normalizedDiff.resolved_findings ?? 0}</div><div class="label">Resolved</div></div>
  <div class="stat"><div class="value ${weightedAfter <= weightedBefore ? 'positive' : 'negative'}">${weightedImprovement}%</div><div class="label">Weighted Improvement</div></div>
</div>
<div class="summary">
  <div class="stat"><div class="value">${weightedBefore}</div><div class="label">Weighted Exposure Before</div></div>
  <div class="stat"><div class="value">${weightedAfter}</div><div class="label">Weighted Exposure After</div></div>
</div>
<div class="legend">Weighted exposure uses severity weights: Critical=4, High=3, Medium=2, Low=1.</div>
<div class="callouts">
  <div class="card">
    <h2>Top Improvements</h2>
    ${topImprovements ? `<ul>${topImprovements}</ul>` : '<p>No major reductions.</p>'}
  </div>
  <div class="card">
    <h2>New Risk Introduced</h2>
    ${newRisks ? `<ul>${newRisks}</ul>` : '<p>No new canonical risks introduced.</p>'}
  </div>
</div>
<h2>What Changed</h2>
<p>${narrativeParts.join(' ')}</p>
${canonicalRows ? `<h2>Canonical Issue Changes</h2><table><thead><tr><th>Owlvex Issue</th><th>Severity</th><th>Before</th><th>After</th><th>Delta</th><th>Reduction</th><th>Frameworks</th></tr></thead><tbody>${canonicalRows}</tbody></table>` : '<p>No canonical issue changes.</p>'}
${newRows ? `<h2>New Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${newRows}</tbody></table>` : '<p>No new findings.</p>'}
${resolvedRows ? `<h2>Resolved Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${resolvedRows}</tbody></table>` : ''}
</body></html>`;
}

export function deactivate() {}
