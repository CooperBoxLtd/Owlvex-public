import * as vscode from 'vscode';
import { buildLicenceBadgeLabel, buildLicenceStatusSummary, buildPlanNextStepGuidance, buildPlanUpgradeMessage, buildScanLimitMessage, canRunScan, hasAiAssistantAccess, hasComparisonAccess, hasPromptEditorAccess, isTrialEndingSoon } from './licence/licenceManager';
import {
    buildBackendAndLicenceReadyChoices,
    buildProviderThrottleOverrideSnippet,
    buildBackendConnectedNoLicenceChoices,
    buildStoredReportComparisonChoice,
    buildStoredScanComparisonChoice,
    buildProviderConnectedChoices,
    buildRegistrationCompletionChoices,
    buildRegistrationSuccessMessage,
    buildVerificationPromptMessage,
    buildUsefulnessPromptMessage,
    clearProviderConnection,
    configureProviderThrottlingForActiveProvider,
    getReportComparisonAnchorScanId,
    getProviderConnectionSettingKeys,
    normalizeComparisonDiff,
    providerAllowsOptionalApiKey,
    resolveProviderApiKeyInput,
    resolveConnectedModelSelection,
    selectLatestTwoReports,
    shouldPromptUsefulnessFeedback,
} from './extension';

const extensionManifest = require('../package.json');

describe('normalizeComparisonDiff', () => {
    it('keeps the current backend contract unchanged', () => {
        const diff = normalizeComparisonDiff({
            new_findings: 2,
            resolved_findings: 1,
            new_finding_details: [{ line: 10 }],
            resolved_finding_details: [{ line: 5 }],
        });

        expect(diff.new_findings).toBe(2);
        expect(diff.resolved_findings).toBe(1);
        expect(diff.new_finding_details).toHaveLength(1);
        expect(diff.resolved_finding_details).toHaveLength(1);
    });

    it('normalizes older array-shaped payloads into count and details fields', () => {
        const diff = normalizeComparisonDiff({
            new_findings: [{ line: 10 }, { line: 20 }],
            resolved_findings: [{ line: 5 }],
        });

        expect(diff.new_findings).toBe(2);
        expect(diff.resolved_findings).toBe(1);
        expect(diff.new_finding_details).toEqual([{ line: 10 }, { line: 20 }]);
        expect(diff.resolved_finding_details).toEqual([{ line: 5 }]);
    });
});

describe('comparison picker helpers', () => {
    it('builds human-readable scan comparison choices from stored scan metadata', () => {
        const choice = buildStoredScanComparisonChoice({
            scanId: '12345678-90ab-cdef-1234-567890abcdef',
            targetLabel: 'tools/demo-app',
            scannedAt: '2026-04-22T19:16:27.000Z',
            result: {
                scanId: '12345678-90ab-cdef-1234-567890abcdef',
                score: 10,
                summary: '',
                findings: [{ severity: 'HIGH' } as any, { severity: 'MEDIUM' } as any],
                positives: [],
                metrics: { critical: 0, high: 1, medium: 1, low: 0 },
                durationMs: 1200,
                model: 'test-foundry-deployment-secondary',
                provider: 'azure-foundry',
                warnings: [],
            } as any,
        } as any);

        expect(choice.label).toBe('tools/demo-app');
        expect(choice.description).toContain('2026-04-22 19:16:27 UTC');
        expect(choice.description).toContain('azure-foundry / test-foundry-deployment-secondary');
        expect(choice.detail).toContain('10.0/10');
        expect(choice.detail).toContain('2 finding(s)');
        expect(choice.detail).toContain('scan 12345678');
    });

    it('builds human-readable report comparison choices from stored report metadata', () => {
        const choice = buildStoredReportComparisonChoice({
            reportId: 'report-12345678',
            reportUri: 'file:///d:/repo/tools/demo/owlvex-scan-report-20260423-120213.md',
            reportFileName: 'owlvex-scan-report-20260423-120213.md',
            targetLabel: 'demo-app workspace',
            createdAt: '2026-04-23T12:02:13.000Z',
            fileCount: 3,
            totalFindings: 7,
            averageScore: 8.7,
            providers: ['azure-foundry'],
            models: ['owlvex-gpt54mini'],
            results: [],
        } as any);

        expect(choice.label).toBe('demo-app workspace');
        expect(choice.description).toContain('2026-04-23 12:02:13 UTC');
        expect(choice.description).toContain('azure-foundry / owlvex-gpt54mini');
        expect(choice.detail).toContain('3 file(s)');
        expect(choice.detail).toContain('7 finding(s)');
        expect(choice.detail).toContain('avg 8.7/10');
        expect(choice.detail).toContain('owlvex-scan-report-20260423-120213.md');
    });

    it('selects the two most recent reports as baseline and current', () => {
        const selection = selectLatestTwoReports([
            {
                reportId: 'older',
                createdAt: '2026-04-23T10:00:00.000Z',
            },
            {
                reportId: 'current',
                createdAt: '2026-04-23T12:00:00.000Z',
            },
            {
                reportId: 'middle',
                createdAt: '2026-04-23T11:00:00.000Z',
            },
        ] as any);

        expect(selection?.baseline.reportId).toBe('middle');
        expect(selection?.current.reportId).toBe('current');
    });

    it('picks the first stored scan id as the report comparison anchor', () => {
        const scanId = getReportComparisonAnchorScanId({
            reportId: 'report-12345678',
            reportUri: 'file:///d:/repo/tools/demo/report.md',
            reportFileName: 'report.md',
            targetLabel: 'demo',
            createdAt: '2026-04-23T12:02:13.000Z',
            fileCount: 2,
            totalFindings: 3,
            averageScore: 7.5,
            providers: ['azure-foundry'],
            models: ['test-foundry-deployment-secondary'],
            results: [
                { uri: 'file:///d:/repo/a.js', result: { scanId: 'scan-a', findings: [] } as any },
                { uri: 'file:///d:/repo/b.js', result: { scanId: 'scan-b', findings: [] } as any },
            ],
        });

        expect(scanId).toBe('scan-a');
    });

    it('returns undefined when a stored report has no scan ids', () => {
        const scanId = getReportComparisonAnchorScanId({
            reportId: 'report-12345678',
            reportUri: 'file:///d:/repo/tools/demo/report.md',
            reportFileName: 'report.md',
            targetLabel: 'demo',
            createdAt: '2026-04-23T12:02:13.000Z',
            fileCount: 1,
            totalFindings: 0,
            averageScore: 0,
            providers: ['azure-foundry'],
            models: ['test-foundry-deployment-secondary'],
            results: [
                { uri: 'file:///d:/repo/a.js', result: { findings: [] } as any },
            ],
        });

        expect(scanId).toBeUndefined();
    });
});

describe('provider setup helpers', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('keeps the user-selected model when discovery returns a different list', () => {
        expect(resolveConnectedModelSelection('gpt-5-mini', ['gpt-4o', 'gpt-4.1'])).toBe('gpt-5-mini');
    });

    it('falls back to the first discovered model when nothing is selected', () => {
        expect(resolveConnectedModelSelection('', ['claude-sonnet-4-6', 'claude-opus-4-6'])).toBe('claude-sonnet-4-6');
    });

    it('marks only custom endpoints as allowing a blank API key', () => {
        expect(providerAllowsOptionalApiKey('custom')).toBe(true);
        expect(providerAllowsOptionalApiKey('azure-foundry')).toBe(false);
        expect(providerAllowsOptionalApiKey('anthropic')).toBe(false);
        expect(providerAllowsOptionalApiKey('openai')).toBe(false);
        expect(providerAllowsOptionalApiKey('mistral')).toBe(false);
        expect(providerAllowsOptionalApiKey('gemini')).toBe(false);
        expect(providerAllowsOptionalApiKey('groq')).toBe(false);
        expect(providerAllowsOptionalApiKey('ollama')).toBe(false);
    });

    it('keeps an existing API key when the user leaves the prompt blank', () => {
        expect(resolveProviderApiKeyInput('', { hasExistingKey: true, allowBlank: false })).toEqual({ action: 'keep' });
        expect(resolveProviderApiKeyInput('   ', { hasExistingKey: true, allowBlank: true })).toEqual({ action: 'keep' });
    });

    it('stores a new API key when the user enters one', () => {
        expect(resolveProviderApiKeyInput('  sk-test  ', { hasExistingKey: true, allowBlank: false })).toEqual({
            action: 'store',
            key: 'sk-test',
        });
    });

    it('allows blank optional API keys only when no saved key exists', () => {
        expect(resolveProviderApiKeyInput('', { hasExistingKey: false, allowBlank: true })).toEqual({ action: 'delete' });
        expect(resolveProviderApiKeyInput('', { hasExistingKey: false, allowBlank: false })).toEqual({ action: 'invalid' });
    });

    it('returns the expected settings to clear for every provider', () => {
        expect(getProviderConnectionSettingKeys('azure-foundry')).toEqual(['foundry.endpoint', 'foundry.model', 'foundry.deployments']);
        expect(getProviderConnectionSettingKeys('anthropic')).toEqual(['anthropic.model']);
        expect(getProviderConnectionSettingKeys('openai')).toEqual(['openai.model']);
        expect(getProviderConnectionSettingKeys('mistral')).toEqual(['mistral.model']);
        expect(getProviderConnectionSettingKeys('gemini')).toEqual(['gemini.model']);
        expect(getProviderConnectionSettingKeys('groq')).toEqual(['groq.model']);
        expect(getProviderConnectionSettingKeys('ollama')).toEqual(['ollama.host', 'ollama.model']);
        expect(getProviderConnectionSettingKeys('custom')).toEqual(['custom.baseUrl', 'custom.model']);
    });

    it('clears saved settings and secrets for Azure Foundry connections', async () => {
        const updateMock = jest.fn();
        const deleteMock = jest.fn();

        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            update: updateMock,
        });
        (vscode.workspace.workspaceFolders as any) = [];

        await clearProviderConnection('azure-foundry', { delete: deleteMock } as any);

        expect(updateMock).toHaveBeenCalledWith('foundry.endpoint', undefined, vscode.ConfigurationTarget.Global);
        expect(updateMock).toHaveBeenCalledWith('foundry.model', undefined, vscode.ConfigurationTarget.Global);
        expect(updateMock).toHaveBeenCalledWith('foundry.deployments', undefined, vscode.ConfigurationTarget.Global);
        expect(deleteMock).toHaveBeenCalledWith('owlvex.foundry.apiKey');
        expect(deleteMock).toHaveBeenCalledWith('owlvex.azure-foundry.apiKey');
    });

    it('builds throttle override snippets with provider defaults', () => {
        expect(JSON.parse(buildProviderThrottleOverrideSnippet('azure-foundry'))).toEqual({
            'azure-foundry': {
                maxConcurrent: 1,
                minSpacingMs: 7000,
                baseBackoffMs: 10000,
                maxBackoffMs: 60000,
                retryAttempts: 2,
            },
        });

        expect(JSON.parse(buildProviderThrottleOverrideSnippet('groq'))).toEqual({
            groq: {
                maxConcurrent: 3,
                minSpacingMs: 100,
                baseBackoffMs: 1500,
                maxBackoffMs: 15000,
                retryAttempts: 2,
            },
        });
    });

    it('falls back to the default hosted profile for unknown providers', () => {
        expect(JSON.parse(buildProviderThrottleOverrideSnippet('unknown-provider'))).toEqual({
            'unknown-provider': {
                maxConcurrent: 2,
                minSpacingMs: 250,
                baseBackoffMs: 2000,
                maxBackoffMs: 30000,
                retryAttempts: 2,
            },
        });
    });
});

describe('extension manifest surface', () => {
    it('contributes the provider throttling command and advanced setting', () => {
        const commandIds = extensionManifest.contributes.commands.map((entry: { command: string }) => entry.command);
        expect(commandIds).toContain('owlvex.configureProviderThrottling');
        expect(commandIds).toContain('owlvex.compareLatestReports');

        expect(extensionManifest.contributes.configuration.properties['owlvex.providerThrottleOverrides']).toMatchObject({
            type: 'object',
            default: {},
        });
    });
});

describe('provider throttling command helper', () => {
    let clipboardWriteTextMock: jest.Mock;

    beforeEach(() => {
        jest.clearAllMocks();
        clipboardWriteTextMock = jest.fn().mockResolvedValue(undefined);
        (vscode as any).env = {
            clipboard: {
                writeText: clipboardWriteTextMock,
            },
        };
        (vscode.commands.executeCommand as jest.Mock).mockResolvedValue(undefined);
        (vscode.window.showInformationMessage as jest.Mock).mockReturnValue(undefined);
    });

    it('opens settings and copies a starter override for the active provider', async () => {
        await configureProviderThrottlingForActiveProvider({
            getActive: () => ({
                id: 'azure-foundry',
                name: 'Azure AI Foundry',
            }),
        });

        expect(clipboardWriteTextMock).toHaveBeenCalledWith(JSON.stringify({
            'azure-foundry': {
                maxConcurrent: 1,
                minSpacingMs: 7000,
                baseBackoffMs: 10000,
                maxBackoffMs: 60000,
                retryAttempts: 2,
            },
        }, null, 2));
        expect(vscode.commands.executeCommand).toHaveBeenCalledWith(
            'workbench.action.openSettings',
            'owlvex.providerThrottleOverrides',
        );
        expect(vscode.window.showInformationMessage).toHaveBeenCalledWith(
            'Owlvex: Opened provider throttling settings. A starter override for Azure AI Foundry was copied to the clipboard.',
        );
    });

    it('uses the active provider identity to tailor the copied snippet and message', async () => {
        await configureProviderThrottlingForActiveProvider({
            getActive: () => ({
                id: 'anthropic',
                name: 'Anthropic',
            }),
        });

        expect(clipboardWriteTextMock).toHaveBeenCalledWith(JSON.stringify({
            anthropic: {
                maxConcurrent: 2,
                minSpacingMs: 500,
                baseBackoffMs: 3000,
                maxBackoffMs: 30000,
                retryAttempts: 2,
            },
        }, null, 2));
        expect(vscode.window.showInformationMessage).toHaveBeenCalledWith(
            'Owlvex: Opened provider throttling settings. A starter override for Anthropic was copied to the clipboard.',
        );
    });
});

describe('plan access helpers', () => {
    it('allows AI assistant access for any validated plan', () => {
        expect(hasAiAssistantAccess({ plan: 'free' } as any)).toBe(true);
        expect(hasAiAssistantAccess({ plan: 'trial' } as any)).toBe(true);
        expect(hasAiAssistantAccess({ plan: 'developer' } as any)).toBe(true);
        expect(hasAiAssistantAccess(null)).toBe(false);
    });

    it('uses feature flags for comparison and prompt editor access', () => {
        expect(hasComparisonAccess({ features: { comparison: false } } as any)).toBe(false);
        expect(hasComparisonAccess({ features: { comparison: true } } as any)).toBe(true);
        expect(hasPromptEditorAccess({ plan: 'free', features: { promptEditor: false } } as any)).toBe(false);
        expect(hasPromptEditorAccess({ plan: 'free', features: { promptEditor: true } } as any)).toBe(true);
        expect(hasPromptEditorAccess({ plan: 'trial', features: { promptEditor: true } } as any)).toBe(true);
    });

    it('returns clear upgrade messages for gated capabilities', () => {
        expect(buildPlanUpgradeMessage('assistant')).toContain('not available');
        expect(buildPlanUpgradeMessage('fix')).toContain('fix previews');
        expect(buildPlanUpgradeMessage('comparison')).toContain('Report comparison');
    });

    it('blocks scans only when the backend says the monthly limit is reached', () => {
        expect(canRunScan(null)).toBe(false);
        expect(canRunScan({ usage: { monthlyLimitReached: false } } as any)).toBe(true);
        expect(canRunScan({ usage: { monthlyLimitReached: true } } as any)).toBe(false);
        expect(buildScanLimitMessage({
            plan: 'free',
            features: { scansPerMonth: 50 },
            usage: { scansThisMonth: 50, monthlyLimitReached: true },
        } as any)).toContain('50/50');
    });

    it('only shows the usefulness prompt once after the first successful free or trial scan', () => {
        expect(shouldPromptUsefulnessFeedback({ plan: 'free' } as any, 1, false)).toBe(true);
        expect(shouldPromptUsefulnessFeedback({ plan: 'trial' } as any, 1, false)).toBe(true);
        expect(shouldPromptUsefulnessFeedback({ plan: 'developer' } as any, 1, false)).toBe(false);
        expect(shouldPromptUsefulnessFeedback({ plan: 'free' } as any, 2, false)).toBe(false);
        expect(shouldPromptUsefulnessFeedback({ plan: 'free' } as any, 1, true)).toBe(false);
    });

    it('uses plan-aware usefulness prompt wording', () => {
        expect(buildUsefulnessPromptMessage({ plan: 'trial' } as any)).toContain('during your trial');
        expect(buildUsefulnessPromptMessage({ plan: 'free' } as any)).toBe('Was this useful?');
    });

    it('builds registration success messaging for free and trial flows', () => {
        expect(buildRegistrationSuccessMessage('free', 'free-user@example.com', {
            plan: 'free',
            teamName: 'free-user',
            features: { scansPerMonth: 50 },
            usage: { scansThisMonth: 0 },
            expiresAt: null,
        } as any)).toContain('Free access registered for free-user@example.com');

        expect(buildRegistrationSuccessMessage('trial', 'trial-user@example.com', {
            plan: 'trial',
            teamName: 'Trial Team',
            features: { scansPerMonth: null },
            usage: { scansThisMonth: 0 },
            expiresAt: '2026-04-26T00:00:00Z',
        } as any)).toContain('Trial started for trial-user@example.com');
    });

    it('builds verification prompt messaging for email and dev-inline delivery', () => {
        const emailPrompt = buildVerificationPromptMessage({
            status: 'verification_required',
            plan: 'trial',
            email: 'trial-user@example.com',
            delivery: 'email',
            expires_in_minutes: 15,
        } as any);
        expect(emailPrompt).toContain('A verification code was sent to trial-user@example.com');
        expect(emailPrompt).toContain('Resend Code');

        const inlinePrompt = buildVerificationPromptMessage({
            status: 'verification_required',
            plan: 'free',
            email: 'free-user@example.com',
            delivery: 'development_inline',
            expires_in_minutes: 15,
            verification_code: '123456',
        } as any);
        expect(inlinePrompt).toContain('Verification code: 123456');
        expect(inlinePrompt).toContain('Resend Code');
    });

    it('builds guided onboarding action choices for backend, registration, and provider setup steps', () => {
        expect(buildBackendConnectedNoLicenceChoices().map(item => item.label)).toEqual([
            'Use Free',
            'Start Trial',
            'Enter Licence',
        ]);
        expect(buildRegistrationCompletionChoices().map(item => item.label)).toEqual([
            'Scan Current File',
            'Scan Workspace',
            'Configure LLM',
        ]);
        expect(buildBackendAndLicenceReadyChoices().map(item => item.label)).toEqual([
            'Scan Current File',
            'Scan Workspace',
            'Configure LLM',
        ]);
        expect(buildProviderConnectedChoices().map(item => item.label)).toEqual([
            'Test Trial Setup',
        ]);
    });

    it('keeps backend setup out of the primary onboarding choices', () => {
        expect(buildBackendConnectedNoLicenceChoices().map(item => item.label)).not.toContain('Configure Backend');
        expect(buildRegistrationCompletionChoices().map(item => item.label)).not.toContain('Configure Backend');
        expect(buildBackendAndLicenceReadyChoices().map(item => item.label)).not.toContain('Configure Backend');
        expect(buildProviderConnectedChoices().map(item => item.label)).not.toContain('Configure Backend');
    });

    it('builds richer licence status summaries for trial and free plans', () => {
        const trialSummary = buildLicenceStatusSummary({
            plan: 'trial',
            teamName: 'Dev Team',
            expiresAt: '2026-04-26T00:00:00Z',
            features: { scansPerMonth: null },
            usage: { scansThisMonth: 3 },
        } as any, new Date('2026-04-19T10:00:00Z'));
        expect(trialSummary).toContain('Licence: Trial');
        expect(trialSummary).toContain('Dev Team');
        expect(trialSummary).toContain('7 days left');

        const freeSummary = buildLicenceStatusSummary({
            plan: 'free',
            teamName: 'Starter',
            features: { scansPerMonth: 50 },
            usage: { scansThisMonth: 4 },
            expiresAt: null,
        } as any);
        expect(freeSummary).toContain('4/50 scans this month');
        expect(buildLicenceBadgeLabel({ plan: 'trial', expiresAt: '2026-04-20T00:00:00Z' } as any, new Date('2026-04-19T10:00:00Z'))).toBe('Trial · 1d left');
        expect(buildLicenceBadgeLabel({ plan: 'developer' } as any)).toBe('Developer');
    });

    it('builds plan-aware next-step guidance including near-expiry trial messaging', () => {
        expect(buildPlanNextStepGuidance({ plan: 'free' } as any)[0]).toContain('full workflow');
        expect(buildPlanNextStepGuidance({
            plan: 'trial',
            expiresAt: '2026-04-20T00:00:00Z',
        } as any, new Date('2026-04-19T10:00:00Z'))[0]).toContain('Trial ending soon');
        expect(isTrialEndingSoon({
            plan: 'trial',
            expiresAt: '2026-04-20T00:00:00Z',
        } as any, 2, new Date('2026-04-19T10:00:00Z'))).toBe(true);
        expect(buildPlanNextStepGuidance({ plan: 'developer' } as any)[0]).toContain('Developer plan active');
    });
});
