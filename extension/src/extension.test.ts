import * as vscode from 'vscode';
import {
    clearProviderConnection,
    getProviderConnectionSettingKeys,
    normalizeComparisonDiff,
    providerAllowsOptionalApiKey,
    resolveConnectedModelSelection,
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
