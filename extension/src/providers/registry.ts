import * as vscode from 'vscode';
import { PROFILE } from '../profile';
import { getSecretStorage } from '../secrets';

export interface CompletionRequest {
    systemPrompt: string;
    userMessage: string;
    model: string;
    temperature: number;
    maxCompletionTokens?: number;
}

export interface CompletionResponse {
    content: string;
    tokenCount?: number;
}

export interface AIProvider {
    id: string;
    name: string;
    selectedModel: string;
    isConfigured(): Promise<boolean>;
    listModels(): Promise<string[]>;
    complete(req: CompletionRequest): Promise<CompletionResponse>;
    testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }>;
}

export function getProviderApiKeySecretName(providerId: string): string {
    const secretId = providerId === 'azure-foundry' ? 'foundry' : providerId;
    return `${PROFILE.secretPrefix}.${secretId}.apiKey`;
}

async function readProviderApiKey(
    secrets: { get(key: string): Thenable<string | undefined> | Promise<string | undefined> | string | undefined } | undefined,
    providerId: string,
): Promise<string | undefined> {
    if (!secrets) return undefined;

    const primary = await secrets.get(getProviderApiKeySecretName(providerId));
    if (primary) return primary;

    // Legacy fallback for Azure Foundry keys stored before the secret-name fix.
    if (providerId === 'azure-foundry') {
        return await secrets.get(`${PROFILE.secretPrefix}.azure-foundry.apiKey`);
    }

    return undefined;
}

function getProviderSecretStorage(): { get(key: string): Thenable<string | undefined> | Promise<string | undefined> | string | undefined } | undefined {
    const initializedSecrets = getSecretStorage();
    if (initializedSecrets) {
        return initializedSecrets;
    }

    const ext = vscode.extensions.getExtension(PROFILE.extensionId);
    return ext?.exports?.secrets;
}

function getPreferredConfigurationTarget(): vscode.ConfigurationTarget {
    return vscode.workspace.workspaceFolders?.length
        ? vscode.ConfigurationTarget.Workspace
        : vscode.ConfigurationTarget.Global;
}

function getGlobalConfigurationTarget(): vscode.ConfigurationTarget {
    return vscode.ConfigurationTarget.Global;
}

function getEffectiveConfigurationTarget(settingKey: string): vscode.ConfigurationTarget {
    const inspected = vscode.workspace.getConfiguration(PROFILE.configSection).inspect(settingKey);
    if (inspected?.workspaceValue !== undefined) {
        return vscode.ConfigurationTarget.Workspace;
    }

    return getGlobalConfigurationTarget();
}

function normalizeConfiguredModels(value: unknown): string[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return [...new Set(
        value
            .map(item => String(item ?? '').trim())
            .filter(Boolean),
    )];
}

export async function persistProviderSetting(
    settingKey: string,
    value: unknown,
    target: vscode.ConfigurationTarget = getPreferredConfigurationTarget(),
): Promise<void> {
    await vscode.workspace
        .getConfiguration(PROFILE.configSection)
        .update(settingKey, value, target);
}

export async function persistProviderConnectionSetting(settingKey: string, value: unknown): Promise<void> {
    await persistProviderSetting(settingKey, value, getGlobalConfigurationTarget());
}

// Chat-capable model prefixes used to filter OpenAI/Groq model lists.
// Keep this broad enough to preserve newer GPT-5/Codex families during setup.
const OPENAI_CHAT_PREFIXES = ['gpt-5', 'gpt-4', 'gpt-3.5', 'o1', 'o3', 'o4', 'chatgpt', 'codex'];
const OPENAI_FALLBACK_MODELS = ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo', 'o1', 'o3-mini'];
const ANTHROPIC_MODELS     = ['claude-opus-4-6', 'claude-sonnet-4-6', 'claude-haiku-4-5-20251001'];
const MISTRAL_FALLBACK     = ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest', 'codestral-latest'];
const GEMINI_FALLBACK      = ['gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash'];
const GROQ_FALLBACK        = ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768', 'gemma2-9b-it'];
const AZURE_CHAT_API_VERSION = '2024-10-21';
const DEFAULT_COMPLETION_TOKENS = 4096;

async function buildProviderErrorMessage(providerName: string, res: Response): Promise<string> {
    let detail = '';

    try {
        const raw = (await res.text()).trim();
        if (raw) {
            detail = raw.replace(/\s+/g, ' ').slice(0, 400);
        }
    } catch {
        // Ignore response-body parsing failures and fall back to the status code.
    }

    return detail
        ? `${providerName} error: ${res.status} ${detail}`
        : `${providerName} error: ${res.status}`;
}

export function isLikelyOpenAIChatModel(modelId: string): boolean {
    const normalized = modelId.trim().toLowerCase();
    return OPENAI_CHAT_PREFIXES.some(prefix => normalized.startsWith(prefix));
}

// ----------------------------------------------------------------
// OpenAI Provider (also used as base for compatible endpoints)
// ----------------------------------------------------------------
class OpenAIProvider implements AIProvider {
    id = 'openai';
    name = 'OpenAI';
    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('openai.model', 'gpt-4o');
    }
    set selectedModel(value: string) {
        void persistProviderConnectionSetting('openai.model', value);
    }

    private async getApiKey(): Promise<string | undefined> {
        return readProviderApiKey(getProviderSecretStorage(), this.id);
    }

    async isConfigured(): Promise<boolean> {
        return !!(await this.getApiKey());
    }

    async listModels(): Promise<string[]> {
        try {
            const key = await this.getApiKey();
            if (!key) return [this.selectedModel];
            const res = await fetch('https://api.openai.com/v1/models', {
                headers: { 'Authorization': `Bearer ${key}` },
            });
            if (!res.ok) return [this.selectedModel];
            const data = await res.json() as any;
            const chat = (data.data as any[])
                .map((m: any) => m.id as string)
                .filter(isLikelyOpenAIChatModel)
                .sort();
            const models = [...new Set([this.selectedModel, ...chat].filter(Boolean))];
            return models.length ? models : [this.selectedModel];
        } catch {
            return [this.selectedModel];
        }
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        const key = await this.getApiKey();
        if (!key) throw new Error('OpenAI API key not configured. Run "Owlvex: Setup AI Connection".');
        const res = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
            body: JSON.stringify({
                model: this.selectedModel,
                max_tokens: req.maxCompletionTokens ?? DEFAULT_COMPLETION_TOKENS,
                temperature: req.temperature,
                messages: [
                    { role: 'system', content: req.systemPrompt },
                    { role: 'user', content: req.userMessage },
                ],
            }),
        });
        if (!res.ok) throw new Error(await buildProviderErrorMessage('OpenAI', res));
        const data = await res.json() as any;
        if (!data.choices?.length) throw new Error('OpenAI returned an empty response');
        return {
            content: data.choices[0].message.content,
            tokenCount: data.usage?.total_tokens,
        };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            const key = await this.getApiKey();
            const res = await fetch('https://api.openai.com/v1/models', {
                headers: { 'Authorization': `Bearer ${key}` },
            });
            return { success: res.ok, latencyMs: Date.now() - start };
        } catch {
            return { success: false, latencyMs: Date.now() - start };
        }
    }
}

// ----------------------------------------------------------------
// Anthropic Provider
// ----------------------------------------------------------------
class AnthropicProvider implements AIProvider {
    id = 'anthropic';
    name = 'Anthropic';
    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('anthropic.model', 'claude-opus-4-6');
    }
    set selectedModel(value: string) {
        void persistProviderConnectionSetting('anthropic.model', value);
    }

    private async getApiKey(): Promise<string | undefined> {
        return readProviderApiKey(getProviderSecretStorage(), this.id);
    }

    async isConfigured(): Promise<boolean> {
        return !!(await this.getApiKey());
    }

    async listModels(): Promise<string[]> {
        return [this.selectedModel];
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        const key = await this.getApiKey();
        if (!key) throw new Error('Anthropic API key not configured. Run "Owlvex: Setup AI Connection".');
        const res = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': key,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model: this.selectedModel,
                max_tokens: req.maxCompletionTokens ?? 8192,
                temperature: req.temperature,
                system: req.systemPrompt,
                messages: [{ role: 'user', content: req.userMessage }],
            }),
        });
        if (!res.ok) throw new Error(await buildProviderErrorMessage('Anthropic', res));
        const data = await res.json() as any;
        if (!data.content?.length) throw new Error('Anthropic returned an empty response');
        return {
            content: data.content[0].text,
            tokenCount: (data.usage?.input_tokens ?? 0) + (data.usage?.output_tokens ?? 0),
        };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            await this.complete({
                systemPrompt: 'Return OK.',
                userMessage: 'ping',
                model: this.selectedModel,
                temperature: 0,
            });
            return { success: true, latencyMs: Date.now() - start };
        } catch {
            return { success: false, latencyMs: Date.now() - start };
        }
    }
}

// ----------------------------------------------------------------
// Azure AI Foundry Provider
// ----------------------------------------------------------------
class AzureFoundryProvider implements AIProvider {
    id = 'azure-foundry';
    name = 'Azure AI Foundry';

    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('foundry.model', '');
    }
    set selectedModel(value: string) {
        void persistProviderConnectionSetting('foundry.model', value);
    }

    private getSelectedDeploymentName(): string {
        const deployment = this.selectedModel.trim();
        if (!deployment) {
            throw new Error('Azure Foundry deployment name not configured. Set owlvex.foundry.model or run "Owlvex: Setup AI Connection".');
        }
        return deployment;
    }

    private async getCredentials(): Promise<{ endpoint: string; apiKey: string } | null> {
        const config = vscode.workspace.getConfiguration(PROFILE.configSection);
        const endpoint = config.get<string>('foundry.endpoint', '').trim().replace(/\/+$/, '');
        const apiKey = await readProviderApiKey(getProviderSecretStorage(), this.id);
        if (!endpoint || !apiKey) return null;
        return { endpoint, apiKey };
    }

    async isConfigured(): Promise<boolean> {
        return !!(await this.getCredentials());
    }

    async listModels(): Promise<string[]> {
        const configuredModels = normalizeConfiguredModels(
            vscode.workspace.getConfiguration(PROFILE.configSection).get<string[]>('foundry.deployments', []),
        );
        const selected = this.selectedModel.trim();
        return [...new Set([selected, ...configuredModels])].filter(Boolean);
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        const creds = await this.getCredentials();
        if (!creds) throw new Error('Azure Foundry not configured. Set owlvex.foundry.endpoint and run "Owlvex: Setup AI Connection".');

        const deployment = this.getSelectedDeploymentName();
        const url = `${creds.endpoint}/openai/deployments/${encodeURIComponent(deployment)}/chat/completions?api-version=${AZURE_CHAT_API_VERSION}`;
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'api-key': creds.apiKey },
            body: JSON.stringify({
                max_completion_tokens: req.maxCompletionTokens ?? DEFAULT_COMPLETION_TOKENS,
                temperature: req.temperature,
                messages: [
                    { role: 'system', content: req.systemPrompt },
                    { role: 'user', content: req.userMessage },
                ],
            }),
        });
        if (!res.ok) throw new Error(await buildProviderErrorMessage('Azure Foundry', res));
        const data = await res.json() as any;
        if (!data.choices?.length) throw new Error('Azure Foundry returned an empty response');
        return {
            content: data.choices[0].message.content,
            tokenCount: data.usage?.total_tokens,
        };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            await this.complete({
                systemPrompt: 'Return OK.',
                userMessage: 'ping',
                model: this.getSelectedDeploymentName(),
                temperature: 0,
            });
            return { success: true, latencyMs: Date.now() - start };
        } catch (error: any) {
            return {
                success: false,
                latencyMs: Date.now() - start,
                message: error?.message || 'Azure Foundry connection failed.',
            };
        }
    }
}

// ----------------------------------------------------------------
// Ollama Provider (local, no key)
// ----------------------------------------------------------------
class OllamaProvider implements AIProvider {
    id = 'ollama';
    name = 'Ollama (local)';

    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('ollama.model', 'qwen2.5:7b');
    }
    set selectedModel(value: string) {
        void vscode.workspace.getConfiguration(PROFILE.configSection).update('ollama.model', value, getGlobalConfigurationTarget());
    }

    private get host(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('ollama.host', 'http://localhost:11434');
    }

    async isConfigured(): Promise<boolean> {
        try {
            const res = await fetch(`${this.host}/api/tags`);
            return res.ok;
        } catch { return false; }
    }

    async listModels(): Promise<string[]> {
        try {
            const res = await fetch(`${this.host}/api/tags`);
            if (!res.ok) return [this.selectedModel];
            const data = await res.json() as any;
            const models = data.models?.map((m: any) => m.name) ?? [];
            return models.length ? models : [this.selectedModel];
        } catch { return [this.selectedModel]; }
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        const res = await fetch(`${this.host}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: this.selectedModel,
                stream: false,
                options: { temperature: req.temperature },
                messages: [
                    { role: 'system', content: req.systemPrompt },
                    { role: 'user', content: req.userMessage },
                ],
            }),
        });
        if (!res.ok) throw new Error(`Ollama error: ${res.status}`);
        const data = await res.json() as any;
        return { content: data.message.content };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            const res = await fetch(`${this.host}/api/tags`);
            return { success: res.ok, latencyMs: Date.now() - start };
        } catch {
            return { success: false, latencyMs: Date.now() - start };
        }
    }
}

// ----------------------------------------------------------------
// Mistral Provider
// ----------------------------------------------------------------
class MistralProvider implements AIProvider {
    id = 'mistral';
    name = 'Mistral';
    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('mistral.model', 'mistral-large-latest');
    }
    set selectedModel(value: string) {
        void persistProviderConnectionSetting('mistral.model', value);
    }

    private async getApiKey(): Promise<string | undefined> {
        return readProviderApiKey(getProviderSecretStorage(), this.id);
    }

    async isConfigured(): Promise<boolean> {
        return !!(await this.getApiKey());
    }

    async listModels(): Promise<string[]> {
        try {
            const key = await this.getApiKey();
            if (!key) return [this.selectedModel];
            const res = await fetch('https://api.mistral.ai/v1/models', {
                headers: { 'Authorization': `Bearer ${key}` },
            });
            if (!res.ok) return [this.selectedModel];
            const data = await res.json() as any;
            const ids = (data.data as any[]).map((m: any) => m.id as string).sort();
            return ids.length ? ids : [this.selectedModel];
        } catch {
            return [this.selectedModel];
        }
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        const key = await this.getApiKey();
        if (!key) throw new Error('Mistral API key not configured. Run "Owlvex: Setup AI Connection".');
        const res = await fetch('https://api.mistral.ai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
            body: JSON.stringify({
                model: this.selectedModel,
                max_tokens: req.maxCompletionTokens ?? DEFAULT_COMPLETION_TOKENS,
                temperature: req.temperature,
                messages: [
                    { role: 'system', content: req.systemPrompt },
                    { role: 'user', content: req.userMessage },
                ],
            }),
        });
        if (!res.ok) throw new Error(await buildProviderErrorMessage('Mistral', res));
        const data = await res.json() as any;
        if (!data.choices?.length) throw new Error('Mistral returned an empty response');
        return {
            content: data.choices[0].message.content,
            tokenCount: data.usage?.total_tokens,
        };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            const key = await this.getApiKey();
            const res = await fetch('https://api.mistral.ai/v1/models', {
                headers: { 'Authorization': `Bearer ${key}` },
            });
            return { success: res.ok, latencyMs: Date.now() - start };
        } catch {
            return { success: false, latencyMs: Date.now() - start };
        }
    }
}

// ----------------------------------------------------------------
// Gemini Provider (Google AI)
// ----------------------------------------------------------------
class GeminiProvider implements AIProvider {
    id = 'gemini';
    name = 'Google Gemini';
    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('gemini.model', 'gemini-1.5-pro');
    }
    set selectedModel(value: string) {
        void persistProviderConnectionSetting('gemini.model', value);
    }

    private async getApiKey(): Promise<string | undefined> {
        return readProviderApiKey(getProviderSecretStorage(), this.id);
    }

    async isConfigured(): Promise<boolean> {
        return !!(await this.getApiKey());
    }

    async listModels(): Promise<string[]> {
        try {
            const key = await this.getApiKey();
            if (!key) return [this.selectedModel];
            const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${key}`);
            if (!res.ok) return [this.selectedModel];
            const data = await res.json() as any;
            const ids = (data.models as any[])
                .filter((m: any) => (m.supportedGenerationMethods as string[])?.includes('generateContent'))
                .map((m: any) => (m.name as string).replace('models/', ''))
                .sort();
            return ids.length ? ids : [this.selectedModel];
        } catch {
            return [this.selectedModel];
        }
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        const key = await this.getApiKey();
        if (!key) throw new Error('Gemini API key not configured. Run "Owlvex: Setup AI Connection".');
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.selectedModel}:generateContent?key=${key}`;
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                system_instruction: { parts: [{ text: req.systemPrompt }] },
                contents: [{ role: 'user', parts: [{ text: req.userMessage }] }],
                generationConfig: { temperature: req.temperature },
            }),
        });
        if (!res.ok) throw new Error(`Gemini error: ${res.status}`);
        const data = await res.json() as any;
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!text) throw new Error('Gemini returned an empty response');
        return {
            content: text,
            tokenCount: data.usageMetadata?.totalTokenCount,
        };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            const key = await this.getApiKey();
            const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${key}`);
            return { success: res.ok, latencyMs: Date.now() - start };
        } catch {
            return { success: false, latencyMs: Date.now() - start };
        }
    }
}

// ----------------------------------------------------------------
// Groq Provider (OpenAI-compatible, ultra-fast inference)
// ----------------------------------------------------------------
class GroqProvider implements AIProvider {
    id = 'groq';
    name = 'Groq';
    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('groq.model', 'llama-3.3-70b-versatile');
    }
    set selectedModel(value: string) {
        void persistProviderConnectionSetting('groq.model', value);
    }

    private async getApiKey(): Promise<string | undefined> {
        return readProviderApiKey(getProviderSecretStorage(), this.id);
    }

    async isConfigured(): Promise<boolean> {
        return !!(await this.getApiKey());
    }

    async listModels(): Promise<string[]> {
        try {
            const key = await this.getApiKey();
            if (!key) return [this.selectedModel];
            const res = await fetch('https://api.groq.com/openai/v1/models', {
                headers: { 'Authorization': `Bearer ${key}` },
            });
            if (!res.ok) return [this.selectedModel];
            const data = await res.json() as any;
            const ids = (data.data as any[]).map((m: any) => m.id as string).sort();
            return ids.length ? ids : [this.selectedModel];
        } catch {
            return [this.selectedModel];
        }
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        const key = await this.getApiKey();
        if (!key) throw new Error('Groq API key not configured. Run "Owlvex: Setup AI Connection".');
        const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
            body: JSON.stringify({
                model: this.selectedModel,
                max_tokens: req.maxCompletionTokens ?? DEFAULT_COMPLETION_TOKENS,
                temperature: req.temperature,
                messages: [
                    { role: 'system', content: req.systemPrompt },
                    { role: 'user', content: req.userMessage },
                ],
            }),
        });
        if (!res.ok) throw new Error(await buildProviderErrorMessage('Groq', res));
        const data = await res.json() as any;
        if (!data.choices?.length) throw new Error('Groq returned an empty response');
        return {
            content: data.choices[0].message.content,
            tokenCount: data.usage?.total_tokens,
        };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            const key = await this.getApiKey();
            const res = await fetch('https://api.groq.com/openai/v1/models', {
                headers: { 'Authorization': `Bearer ${key}` },
            });
            return { success: res.ok, latencyMs: Date.now() - start };
        } catch {
            return { success: false, latencyMs: Date.now() - start };
        }
    }
}

// ----------------------------------------------------------------
// Custom Provider (any OpenAI-compatible endpoint)
// ----------------------------------------------------------------
class CustomProvider implements AIProvider {
    id = 'custom';
    name = 'Custom Endpoint';

    get selectedModel(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('custom.model', 'custom-model');
    }
    set selectedModel(value: string) {
        void vscode.workspace.getConfiguration(PROFILE.configSection).update('custom.model', value, getGlobalConfigurationTarget());
    }

    private get baseUrl(): string {
        return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('custom.baseUrl', '');
    }

    private async getApiKey(): Promise<string | undefined> {
        return readProviderApiKey(getProviderSecretStorage(), this.id);
    }

    async isConfigured(): Promise<boolean> {
        return !!this.baseUrl;
    }

    async listModels(): Promise<string[]> {
        // Try to fetch from the custom endpoint; fall back to whatever model is configured.
        try {
            if (!this.baseUrl) return [this.selectedModel];
            const key = await this.getApiKey();
            const res = await fetch(`${this.baseUrl}/v1/models`, {
                headers: key ? { 'Authorization': `Bearer ${key}` } : {},
            });
            if (!res.ok) return [this.selectedModel];
            const data = await res.json() as any;
            const ids = (data.data as any[]).map((m: any) => m.id as string).sort();
            return ids.length ? ids : [this.selectedModel];
        } catch {
            return [this.selectedModel];
        }
    }

    async complete(req: CompletionRequest): Promise<CompletionResponse> {
        if (!this.baseUrl) throw new Error(`Custom endpoint base URL not configured. Set ${PROFILE.configSection}.custom.baseUrl.`);
        const key = await this.getApiKey();
        const res = await fetch(`${this.baseUrl}/v1/chat/completions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(key ? { 'Authorization': `Bearer ${key}` } : {}),
            },
            body: JSON.stringify({
                model: this.selectedModel,
                temperature: req.temperature,
                messages: [
                    { role: 'system', content: req.systemPrompt },
                    { role: 'user', content: req.userMessage },
                ],
            }),
        });
        if (!res.ok) throw new Error(`Custom endpoint error: ${res.status}`);
        const data = await res.json() as any;
        if (!data.choices?.length) throw new Error('Custom endpoint returned an empty response');
        return {
            content: data.choices[0].message.content,
            tokenCount: data.usage?.total_tokens,
        };
    }

    async testConnection(): Promise<{ success: boolean; latencyMs: number; message?: string }> {
        const start = Date.now();
        try {
            if (!this.baseUrl) return { success: false, latencyMs: 0 };
            const key = await this.getApiKey();
            const res = await fetch(`${this.baseUrl}/v1/models`, {
                headers: key ? { 'Authorization': `Bearer ${key}` } : {},
            });
            return { success: res.ok, latencyMs: Date.now() - start };
        } catch {
            return { success: false, latencyMs: Date.now() - start };
        }
    }
}

// ----------------------------------------------------------------
// Provider Registry
// ----------------------------------------------------------------
export class ProviderRegistry {
    private providers = new Map<string, AIProvider>([
        ['openai',        new OpenAIProvider()],
        ['anthropic',     new AnthropicProvider()],
        ['azure-foundry', new AzureFoundryProvider()],
        ['ollama',        new OllamaProvider()],
        ['mistral',       new MistralProvider()],
        ['gemini',        new GeminiProvider()],
        ['groq',          new GroqProvider()],
        ['custom',        new CustomProvider()],
    ]);

    getProvider(id: string): AIProvider | undefined {
        return this.providers.get(id);
    }

    getActive(): AIProvider {
        const id = vscode.workspace.getConfiguration(PROFILE.configSection).get<string>('provider', 'openai');
        return this.providers.get(id) ?? this.providers.get('openai')!;
    }

    async setActiveProvider(id: string): Promise<void> {
        await vscode.workspace.getConfiguration(PROFILE.configSection).update('provider', id, getEffectiveConfigurationTarget('provider'));
    }

    allProviders(): AIProvider[] {
        return Array.from(this.providers.values());
    }
}
