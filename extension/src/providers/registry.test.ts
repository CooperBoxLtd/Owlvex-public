/**
 * Unit tests for ProviderRegistry — provider lookup, active provider selection,
 * and all provider list coverage.
 */
import { ProviderRegistry } from './registry';

// workspace.getConfiguration mock returns a cfg object — we control it per test.
import * as vscode from 'vscode';

describe('ProviderRegistry', () => {
    let registry: ProviderRegistry;

    beforeEach(() => {
        jest.clearAllMocks();
        registry = new ProviderRegistry();
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
    });

    describe('provider model lists', () => {
        it('OpenAI lists expected models', async () => {
            const models = await registry.getProvider('openai')!.listModels();
            expect(models).toContain('gpt-4o');
            expect(models).toContain('o1');
        });

        it('Anthropic lists expected models', async () => {
            const models = await registry.getProvider('anthropic')!.listModels();
            expect(models).toContain('claude-opus-4-6');
            expect(models).toContain('claude-sonnet-4-6');
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
    });
});
