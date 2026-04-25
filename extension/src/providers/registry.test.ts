/**
 * Unit tests for ProviderRegistry — provider lookup, active provider selection,
 * and all provider list coverage.
 */
import { getProviderApiKeySecretName, isLikelyOpenAIChatModel, ProviderRegistry } from './registry';

// workspace.getConfiguration mock returns a cfg object — we control it per test.
import * as vscode from 'vscode';

describe('ProviderRegistry', () => {
    let registry: ProviderRegistry;
    let configState: Record<string, any>;
    let updateMock: jest.Mock;
    let secretGetMock: jest.Mock;

    beforeEach(() => {
        jest.clearAllMocks();
        jest.useRealTimers();
        configState = {
            provider: 'openai',
            'foundry.endpoint': 'https://example.openai.azure.com',
            'foundry.model': 'test-foundry-deployment-primary',
            'foundry.deployments': ['test-foundry-deployment-primary', 'test-foundry-deployment-secondary'],
            'providerThrottleOverrides': {},
        };
        updateMock = jest.fn(async (key: string, value: any) => {
            configState[key] = value;
        });
        (vscode.workspace.getConfiguration as jest.Mock).mockImplementation(() => ({
            get: (key: string, def: any) => key in configState ? configState[key] : def,
            update: updateMock,
        }));
        secretGetMock = jest.fn(async (key: string) => key === 'owlvex.foundry.apiKey' ? 'test-foundry-key' : undefined);
        (vscode.extensions.getExtension as jest.Mock).mockReturnValue({
            exports: { secrets: { get: secretGetMock, store: jest.fn(), delete: jest.fn() } },
        });
        registry = new ProviderRegistry();
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    describe('getProvider', () => {
        it('returns OpenAI provider by id', () => {
            const p = registry.getProvider('openai');
            expect(p).toBeDefined();
            expect(p!.id).toBe('openai');
            expect(p!.name).toBe('OpenAI');
        });

        it('returns Anthropic provider by id', () => {
            const p = registry.getProvider('anthropic');
            expect(p!.id).toBe('anthropic');
        });

        it('returns Azure Foundry provider by id', () => {
            const p = registry.getProvider('azure-foundry');
            expect(p!.id).toBe('azure-foundry');
        });

        it('returns Ollama provider by id', () => {
            const p = registry.getProvider('ollama');
            expect(p!.id).toBe('ollama');
        });

        it('returns Mistral provider by id', () => {
            const p = registry.getProvider('mistral');
            expect(p!.id).toBe('mistral');
        });

        it('returns Gemini provider by id', () => {
            const p = registry.getProvider('gemini');
            expect(p!.id).toBe('gemini');
        });

        it('returns Groq provider by id', () => {
            const p = registry.getProvider('groq');
            expect(p!.id).toBe('groq');
        });

        it('returns Custom provider by id', () => {
            const p = registry.getProvider('custom');
            expect(p!.id).toBe('custom');
        });

        it('returns undefined for unknown provider id', () => {
            expect(registry.getProvider('nonexistent')).toBeUndefined();
        });
    });

    describe('allProviders', () => {
        it('returns all 8 registered providers', () => {
            const all = registry.allProviders();
            expect(all).toHaveLength(8);
        });

        it('each provider has required interface properties', () => {
            registry.allProviders().forEach(p => {
                expect(typeof p.id).toBe('string');
                expect(typeof p.name).toBe('string');
                expect(typeof p.complete).toBe('function');
                expect(typeof p.isConfigured).toBe('function');
                expect(typeof p.listModels).toBe('function');
                expect(typeof p.testConnection).toBe('function');
            });
        });
    });

    describe('getActive', () => {
        it('returns openai provider when config says openai', () => {
            (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
                get: (key: string, def: any) => key === 'provider' ? 'openai' : def,
            });
            const active = registry.getActive();
            expect(active.id).toBe('openai');
        });

        it('returns anthropic provider when config says anthropic', () => {
            (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
                get: (key: string, def: any) => key === 'provider' ? 'anthropic' : def,
            });
            expect(registry.getActive().id).toBe('anthropic');
        });

        it('falls back to openai for unknown provider id in config', () => {
            (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
                get: (_key: string, def: any) => 'totally-unknown',
            });
            expect(registry.getActive().id).toBe('openai');
        });

        it('updates the workspace override target when provider is overridden at workspace scope', async () => {
            (vscode.workspace.getConfiguration as jest.Mock).mockImplementation(() => ({
                get: (key: string, def: any) => key in configState ? configState[key] : def,
                inspect: (key: string) => key === 'provider'
                    ? { workspaceValue: 'azure-foundry', globalValue: 'anthropic' }
                    : { workspaceValue: undefined, globalValue: undefined },
                update: updateMock,
            }));

            await registry.setActiveProvider('anthropic');

            expect(updateMock).toHaveBeenCalledWith('provider', 'anthropic', vscode.ConfigurationTarget.Workspace);
        });
    });

    describe('provider model lists', () => {
        it('OpenAI lists expected models', async () => {
            const models = await registry.getProvider('openai')!.listModels();
            expect(models).toEqual(['gpt-4o']);
        });

        it('keeps GPT-5 and Codex-family models when OpenAI advertises them', async () => {
            configState['openai.model'] = 'gpt-5-mini';
            secretGetMock.mockImplementation(async (key: string) => {
                if (key === 'owlvex.openai.apiKey') {
                    return 'test-openai-key';
                }
                return undefined;
            });
            (global.fetch as jest.Mock) = jest.fn().mockResolvedValue({
                ok: true,
                json: async () => ({
                    data: [
                        { id: 'gpt-5-mini' },
                        { id: 'gpt-5' },
                        { id: 'codex-mini-latest' },
                        { id: 'text-embedding-3-large' },
                    ],
                }),
            });

            const models = await registry.getProvider('openai')!.listModels();
            expect(models).toEqual(['gpt-5-mini', 'codex-mini-latest', 'gpt-5']);
        });

        it('Anthropic lists expected models', async () => {
            const models = await registry.getProvider('anthropic')!.listModels();
            expect(models).toEqual(['claude-opus-4-6']);
        });

        it('Mistral lists expected models', async () => {
            const models = await registry.getProvider('mistral')!.listModels();
            expect(models).toContain('mistral-large-latest');
        });

        it('Gemini lists expected models', async () => {
            const models = await registry.getProvider('gemini')!.listModels();
            expect(models).toContain('gemini-1.5-pro');
        });

        it('Groq lists expected models', async () => {
            const models = await registry.getProvider('groq')!.listModels();
            expect(models).toContain('llama-3.3-70b-versatile');
        });

        it('Ollama returns non-empty fallback list', async () => {
            (global.fetch as jest.Mock) = jest.fn().mockRejectedValue(new Error('not running'));
            const models = await registry.getProvider('ollama')!.listModels();
            expect(models.length).toBeGreaterThan(0);
        });

        it('treats custom endpoints without auth as configured when a base URL exists', async () => {
            configState['custom.baseUrl'] = 'https://custom.local';
            const configured = await registry.getProvider('custom')!.isConfigured();
            expect(configured).toBe(true);
        });
    });

    describe('OpenAI model filtering', () => {
        it('recognizes current chat-capable OpenAI model families', () => {
            expect(isLikelyOpenAIChatModel('gpt-5')).toBe(true);
            expect(isLikelyOpenAIChatModel('codex-mini-latest')).toBe(true);
            expect(isLikelyOpenAIChatModel('text-embedding-3-large')).toBe(false);
        });
    });

    describe('azure foundry configuration', () => {
        it('maps Azure Foundry secrets to the shared foundry namespace', () => {
            expect(getProviderApiKeySecretName('azure-foundry')).toBe('owlvex.foundry.apiKey');
        });

        it('reads selected deployment name from configuration', () => {
            const provider = registry.getProvider('azure-foundry')!;
            expect(provider.selectedModel).toBe('test-foundry-deployment-primary');
        });

        it('lists configured deployment names for Azure Foundry model switching', async () => {
            const provider = registry.getProvider('azure-foundry')!;
            const models = await provider.listModels();
            expect(models).toEqual(['test-foundry-deployment-primary', 'test-foundry-deployment-secondary']);
        });

        it('persists selected deployment name back to configuration', async () => {
            const provider = registry.getProvider('azure-foundry')!;
            provider.selectedModel = 'owlvex-security-chat';
            await Promise.resolve();
            expect(updateMock).toHaveBeenCalledWith('foundry.model', 'owlvex-security-chat', expect.anything());
        });

        it('can persist a selected deployment name through the registry', async () => {
            await registry.setProviderModel('azure-foundry', 'test-foundry-deployment-tertiary');

            expect(updateMock).toHaveBeenCalledWith('foundry.model', 'test-foundry-deployment-tertiary', vscode.ConfigurationTarget.Global);
        });

        it('persists the selected deployment to workspace scope when the deployment is overridden there', async () => {
            (vscode.workspace.getConfiguration as jest.Mock).mockImplementation(() => ({
                get: (key: string, def: any) => key in configState ? configState[key] : def,
                inspect: (key: string) => key === 'foundry.model'
                    ? { workspaceValue: 'test-foundry-deployment-primary', globalValue: 'test-foundry-deployment-secondary' }
                    : { workspaceValue: undefined, globalValue: undefined },
                update: updateMock,
            }));

            await registry.setProviderModel('azure-foundry', 'test-foundry-deployment-tertiary');

            expect(updateMock).toHaveBeenCalledWith('foundry.model', 'test-foundry-deployment-tertiary', vscode.ConfigurationTarget.Workspace);
        });

        it('fails connection test when configured deployment is missing', async () => {
            (global.fetch as jest.Mock) = jest.fn().mockResolvedValue({
                ok: false,
                status: 404,
                headers: { get: () => null },
                text: async () => '',
            });

            const provider = registry.getProvider('azure-foundry')!;
            const result = await provider.testConnection();
            expect(result.success).toBe(false);
            expect(result.message).toContain('Azure Foundry error: 404');
        });

        it('fails early when no Azure deployment name is configured', async () => {
            configState['foundry.model'] = '';

            const provider = registry.getProvider('azure-foundry')!;
            const result = await provider.testConnection();

            expect(result.success).toBe(false);
            expect(result.message).toContain('deployment name not configured');
        });

        it('tests Azure connection against the configured deployment chat endpoint', async () => {
            const fetchMock = jest.fn().mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => ({
                    choices: [{ message: { content: 'OK' } }],
                    usage: { total_tokens: 12 },
                }),
            });
            (global.fetch as jest.Mock) = fetchMock;

            const provider = registry.getProvider('azure-foundry')!;
            const result = await provider.testConnection();

            expect(result.success).toBe(true);
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/openai/deployments/test-foundry-deployment-primary/chat/completions?api-version=2024-10-21'),
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/json',
                        'api-key': 'test-foundry-key',
                    }),
                }),
            );
        });

        it('uses configured deployment in completion URL', async () => {
            const fetchMock = jest.fn()
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        choices: [{ message: { content: 'ok' } }],
                        usage: { total_tokens: 12 },
                    }),
                });
            (global.fetch as jest.Mock) = fetchMock;

            const provider = registry.getProvider('azure-foundry')!;
            await provider.complete({
                systemPrompt: 'system',
                userMessage: 'user',
                model: provider.selectedModel,
                temperature: 0,
            });

            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/openai/deployments/test-foundry-deployment-primary/chat/completions?api-version=2024-10-21'),
                expect.objectContaining({
                    body: expect.stringContaining('"max_completion_tokens":4096'),
                }),
            );
        });

        it('serializes Azure Foundry requests behind a shared throttle', async () => {
            jest.useFakeTimers();
            const fetchMock = jest.fn()
                .mockResolvedValue({
                    ok: true,
                    json: async () => ({
                        choices: [{ message: { content: 'ok' } }],
                        usage: { total_tokens: 12 },
                    }),
                });
            (global.fetch as jest.Mock) = fetchMock;

            const provider = registry.getProvider('azure-foundry')!;
            const first = provider.complete({
                systemPrompt: 'system',
                userMessage: 'first',
                model: provider.selectedModel,
                temperature: 0,
            });
            const second = provider.complete({
                systemPrompt: 'system',
                userMessage: 'second',
                model: provider.selectedModel,
                temperature: 0,
            });

            await jest.advanceTimersByTimeAsync(0);
            expect(fetchMock).toHaveBeenCalledTimes(1);

            await jest.advanceTimersByTimeAsync(6999);
            expect(fetchMock).toHaveBeenCalledTimes(1);

            await jest.advanceTimersByTimeAsync(1);
            await Promise.all([first, second]);
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        it('retries Azure Foundry requests after a 429 with retry-after guidance', async () => {
            jest.useFakeTimers();
            const fetchMock = jest.fn()
                .mockResolvedValueOnce({
                    ok: false,
                    status: 429,
                    headers: { get: (name: string) => name.toLowerCase() === 'retry-after' ? '1' : null },
                    text: async () => 'rate limited',
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        choices: [{ message: { content: 'ok' } }],
                        usage: { total_tokens: 12 },
                    }),
                });
            (global.fetch as jest.Mock) = fetchMock;

            const provider = registry.getProvider('azure-foundry')!;
            const resultPromise = provider.complete({
                systemPrompt: 'system',
                userMessage: 'retry me',
                model: provider.selectedModel,
                temperature: 0,
            });

            await jest.advanceTimersByTimeAsync(0);
            expect(fetchMock).toHaveBeenCalledTimes(1);

            await jest.advanceTimersByTimeAsync(12000);
            const result = await resultPromise;
            expect(result.content).toBe('ok');
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        it('does not proactively throttle Anthropic by default without field evidence of 429s', async () => {
            jest.useFakeTimers();
            secretGetMock.mockImplementation(async (key: string) => {
                if (key === 'owlvex.anthropic.apiKey') {
                    return 'test-anthropic-key';
                }
                return undefined;
            });
            const fetchMock = jest.fn()
                .mockResolvedValue({
                    ok: true,
                    json: async () => ({
                        content: [{ text: 'ok' }],
                        usage: { input_tokens: 5, output_tokens: 2 },
                    }),
                });
            (global.fetch as jest.Mock) = fetchMock;

            const provider = registry.getProvider('anthropic')!;
            const first = provider.complete({
                systemPrompt: 'system',
                userMessage: 'first',
                model: provider.selectedModel,
                temperature: 0,
            });
            const second = provider.complete({
                systemPrompt: 'system',
                userMessage: 'second',
                model: provider.selectedModel,
                temperature: 0,
            });

            await jest.advanceTimersByTimeAsync(0);
            await Promise.all([first, second]);
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });
    });

    describe('shared provider throttling', () => {
        it('retries generic OpenAI-compatible rate limits before surfacing failure', async () => {
            jest.useFakeTimers();
            configState.provider = 'openai';
            secretGetMock.mockImplementation(async (key: string) => {
                if (key === 'owlvex.openai.apiKey') {
                    return 'test-openai-key';
                }
                return undefined;
            });
            const fetchMock = jest.fn()
                .mockResolvedValueOnce({
                    ok: false,
                    status: 429,
                    headers: { get: () => null },
                    text: async () => 'Too Many Requests',
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        choices: [{ message: { content: 'ok' } }],
                        usage: { total_tokens: 10 },
                    }),
                });
            (global.fetch as jest.Mock) = fetchMock;

            const provider = registry.getProvider('openai')!;
            const resultPromise = provider.complete({
                systemPrompt: 'system',
                userMessage: 'ping',
                model: provider.selectedModel,
                temperature: 0,
            });

            await jest.advanceTimersByTimeAsync(0);
            expect(fetchMock).toHaveBeenCalledTimes(1);

            await jest.advanceTimersByTimeAsync(3000);
            const result = await resultPromise;
            expect(result.content).toBe('ok');
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        it('honors configured throttle overrides for a provider', async () => {
            jest.useFakeTimers();
            configState['providerThrottleOverrides'] = {
                'azure-foundry': {
                    minSpacingMs: 1000,
                    maxConcurrent: 1,
                },
            };

            const fetchMock = jest.fn().mockResolvedValue({
                ok: true,
                json: async () => ({
                    choices: [{ message: { content: 'ok' } }],
                    usage: { total_tokens: 12 },
                }),
            });
            (global.fetch as jest.Mock) = fetchMock;
            registry = new ProviderRegistry();

            const provider = registry.getProvider('azure-foundry')!;
            const first = provider.complete({
                systemPrompt: 'system',
                userMessage: 'first',
                model: provider.selectedModel,
                temperature: 0,
            });
            const second = provider.complete({
                systemPrompt: 'system',
                userMessage: 'second',
                model: provider.selectedModel,
                temperature: 0,
            });

            await jest.advanceTimersByTimeAsync(0);
            expect(fetchMock).toHaveBeenCalledTimes(1);

            await jest.advanceTimersByTimeAsync(999);
            expect(fetchMock).toHaveBeenCalledTimes(1);

            await jest.advanceTimersByTimeAsync(1);
            await Promise.all([first, second]);
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });
    });
});
