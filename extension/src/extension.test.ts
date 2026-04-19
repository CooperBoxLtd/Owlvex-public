import * as vscode from 'vscode';
import { buildLicenceBadgeLabel, buildLicenceStatusSummary, buildPlanNextStepGuidance, buildPlanUpgradeMessage, buildScanLimitMessage, canRunScan, hasAiAssistantAccess, hasComparisonAccess, hasPromptEditorAccess, isTrialEndingSoon } from './licence/licenceManager';
import {
    buildRegistrationSuccessMessage,
    buildVerificationPromptMessage,
    buildUsefulnessPromptMessage,
    clearProviderConnection,
    getProviderConnectionSettingKeys,
    normalizeComparisonDiff,
    providerAllowsOptionalApiKey,
    resolveConnectedModelSelection,
    shouldPromptUsefulnessFeedback,
} from './extension';

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
        expect(buildPlanUpgradeMessage('comparison')).toContain('Scan comparison');
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
        expect(buildVerificationPromptMessage({
            status: 'verification_required',
            plan: 'trial',
            email: 'trial-user@example.com',
            delivery: 'email',
            expires_in_minutes: 15,
        } as any)).toContain('A verification code was sent to trial-user@example.com');

        expect(buildVerificationPromptMessage({
            status: 'verification_required',
            plan: 'free',
            email: 'free-user@example.com',
            delivery: 'development_inline',
            expires_in_minutes: 15,
            verification_code: '123456',
        } as any)).toContain('Verification code: 123456');
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
