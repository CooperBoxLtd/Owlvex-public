import * as crypto from 'crypto';
import { RulePackClient } from './packClient';

describe('RulePackClient', () => {
    const stableStringify = (value: unknown): string => {
        if (Array.isArray(value)) {
            return `[${value.map(stableStringify).join(',')}]`;
        }

        if (value && typeof value === 'object') {
            const entries = Object.entries(value as Record<string, unknown>)
                .sort(([left], [right]) => left.localeCompare(right))
                .map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`);
            return `{${entries.join(',')}}`;
        }

        return JSON.stringify(value);
    };

    const createStorage = () => {
        const values = new Map<string, unknown>();
        return {
            get: jest.fn((key: string) => values.get(key)),
            update: jest.fn(async (key: string, value: unknown) => {
                values.set(key, value);
            }),
        } as any;
    };

    const createJsonResponse = (body: unknown, ok = true, status = 200) => ({
        ok,
        status,
        json: jest.fn().mockResolvedValue(body),
    }) as any;

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('caches the manifest after a successful sync', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);

        (global.fetch as jest.Mock) = jest.fn().mockResolvedValue(createJsonResponse({
            schema_version: 'owlvex.rulepack.manifest-list.v1',
            packs: [
                {
                    schema_version: 'owlvex.rulepack.manifest.v1',
                    pack_id: 'owlvex.issue-pack.v1',
                    pack_type: 'issue-pack',
                    pack_version: 1,
                    sha256: 'abc',
                    size_bytes: 10,
                    frameworks: [],
                    download_path: '/v1/packs/owlvex.issue-pack.v1',
                },
            ],
        }));

        const manifest = await client.syncManifest('https://api.example.test', 'licence-key');

        expect(manifest.packs).toHaveLength(1);
        expect(manifest.fetched_at).toBeTruthy();
        expect(client.getCachedManifest()?.packs[0].pack_id).toBe('owlvex.issue-pack.v1');
    });

    it('downloads and caches a pack when the integrity hash matches', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);
        const artifactPayload = {
            schema_version: 'owlvex.issue-pack.v1',
            pack_id: 'owlvex.core-security.2026.1',
        };
        const artifactHash = crypto.createHash('sha256').update(stableStringify(artifactPayload)).digest('hex');

        (global.fetch as jest.Mock) = jest.fn().mockResolvedValue(createJsonResponse({
            schema_version: 'owlvex.rulepack.artifact.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            sha256: artifactHash,
            size_bytes: 10,
            frameworks: [],
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            artifact: artifactPayload,
        }));

        const manifest = {
            schema_version: 'owlvex.rulepack.manifest.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            sha256: artifactHash,
            size_bytes: 10,
            frameworks: [],
            download_path: '/v1/packs/owlvex.issue-pack.v1',
        };

        const artifact = await client.fetchPackArtifact('https://api.example.test', 'licence-key', manifest);

        expect(artifact.artifact).toEqual(artifactPayload);
        expect(client.getCachedPack('owlvex.issue-pack.v1')?.artifact).toEqual(artifactPayload);
    });

    it('rejects a pack when the integrity hash does not match', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);

        (global.fetch as jest.Mock) = jest.fn().mockResolvedValue(createJsonResponse({
            schema_version: 'owlvex.rulepack.artifact.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            sha256: 'wrong',
            size_bytes: 10,
            frameworks: [],
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            artifact: { schema_version: 'owlvex.issue-pack.v1' },
        }));

        await expect(client.fetchPackArtifact('https://api.example.test', 'licence-key', {
            schema_version: 'owlvex.rulepack.manifest.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            sha256: 'wrong',
            size_bytes: 10,
            frameworks: [],
            download_path: '/v1/packs/owlvex.issue-pack.v1',
        })).rejects.toThrow(/integrity check failed/i);
    });
});
