import * as crypto from 'crypto';
import { RulePackClient } from './packClient';

describe('RulePackClient', () => {
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPdEILhBPJPbXD/zvw5DvKx47+DNVrNmDJWYbKLfFTze
-----END PRIVATE KEY-----`;
    const nextPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILsMdDJI53FIJrYGKqbkgwYbqqfgRhdbuw8ulJquXsTQ
-----END PRIVATE KEY-----`;

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

    const signManifest = (entry: Record<string, unknown>, keyPem = privateKeyPem): string =>
        crypto.sign(null, Buffer.from(stableStringify(entry)), keyPem).toString('base64');

    const createStorage = () => {
        const values = new Map<string, unknown>();
        const storage: any = {
            get: jest.fn((key: string) => values.get(key)),
            update: jest.fn(async (key: string, value: unknown) => {
                if (typeof value === 'undefined') {
                    values.delete(key);
                } else {
                    values.set(key, value);
                }
            }),
        };
        Object.defineProperty(storage, 'keys', {
            get: () => [...values.keys()],
        });
        return storage;
    };

    const createJsonResponse = (body: unknown, ok = true, status = 200) => ({
        ok,
        status,
        json: jest.fn().mockResolvedValue(body),
    }) as any;
    const licenceScope = { plan: 'developer', frameworks: ['OWASP', 'STRIDE'] };

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
                    issued_at: '2026-04-14T00:00:00Z',
                    expires_at: '2026-05-14T00:00:00Z',
                    sha256: 'abc',
                    size_bytes: 10,
                    frameworks: [],
                    licence_scope: licenceScope,
                    download_path: '/v1/packs/owlvex.issue-pack.v1',
                    signature_algorithm: 'ed25519',
                    key_id: 'owlvex-dev-ed25519-2026-04',
                    signature: signManifest({
                        schema_version: 'owlvex.rulepack.manifest.v1',
                        pack_id: 'owlvex.issue-pack.v1',
                        pack_type: 'issue-pack',
                        pack_version: 1,
                        issued_at: '2026-04-14T00:00:00Z',
                        expires_at: '2026-05-14T00:00:00Z',
                        sha256: 'abc',
                        size_bytes: 10,
                        frameworks: [],
                        licence_scope: licenceScope,
                        download_path: '/v1/packs/owlvex.issue-pack.v1',
                        signature_algorithm: 'ed25519',
                        key_id: 'owlvex-dev-ed25519-2026-04',
                    }),
                },
            ],
        }));

        const manifest = await client.syncManifest('https://api.example.test', 'licence-key');

        expect(manifest.packs).toHaveLength(1);
        expect(manifest.fetched_at).toBeTruthy();
        expect(client.getCachedManifest()?.packs[0].pack_id).toBe('owlvex.issue-pack.v1');
        expect(client.getCachedManifestFreshness()).toBe('fresh');
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
            issued_at: '2026-04-14T00:00:00Z',
            expires_at: '2026-05-14T00:00:00Z',
            sha256: artifactHash,
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            artifact: artifactPayload,
        }));

        const manifest = {
            schema_version: 'owlvex.rulepack.manifest.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            issued_at: '2026-04-14T00:00:00Z',
            expires_at: '2026-05-14T00:00:00Z',
            sha256: artifactHash,
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            signature_algorithm: 'ed25519',
            key_id: 'owlvex-dev-ed25519-2026-04',
            signature: signManifest({
                schema_version: 'owlvex.rulepack.manifest.v1',
                pack_id: 'owlvex.issue-pack.v1',
                pack_type: 'issue-pack',
                pack_version: 1,
                issued_at: '2026-04-14T00:00:00Z',
                expires_at: '2026-05-14T00:00:00Z',
                sha256: artifactHash,
                size_bytes: 10,
                frameworks: [],
                licence_scope: licenceScope,
                download_path: '/v1/packs/owlvex.issue-pack.v1',
                signature_algorithm: 'ed25519',
                key_id: 'owlvex-dev-ed25519-2026-04',
            }),
        };

        const artifact = await client.fetchPackArtifact('https://api.example.test', 'licence-key', manifest);

        expect(artifact.artifact).toEqual(artifactPayload);
        expect(client.getCachedPack('owlvex.issue-pack.v1')?.artifact).toEqual(artifactPayload);
    });

    it('reuses a cached artifact when it still matches the signed manifest entry', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);
        const artifactPayload = {
            schema_version: 'owlvex.issue-pack.v1',
            pack_id: 'owlvex.core-security.2026.1',
        };
        const artifactHash = crypto.createHash('sha256').update(stableStringify(artifactPayload)).digest('hex');
        const manifest = {
            schema_version: 'owlvex.rulepack.manifest.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            issued_at: '2026-04-14T00:00:00Z',
            expires_at: '2026-05-14T00:00:00Z',
            sha256: artifactHash,
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            signature_algorithm: 'ed25519',
            key_id: 'owlvex-dev-ed25519-2026-04',
            signature: signManifest({
                schema_version: 'owlvex.rulepack.manifest.v1',
                pack_id: 'owlvex.issue-pack.v1',
                pack_type: 'issue-pack',
                pack_version: 1,
                issued_at: '2026-04-14T00:00:00Z',
                expires_at: '2026-05-14T00:00:00Z',
                sha256: artifactHash,
                size_bytes: 10,
                frameworks: [],
                licence_scope: licenceScope,
                download_path: '/v1/packs/owlvex.issue-pack.v1',
                signature_algorithm: 'ed25519',
                key_id: 'owlvex-dev-ed25519-2026-04',
            }),
        };

        await storage.update('owlvex.rulepacks.pack.owlvex.issue-pack.v1', {
            ...manifest,
            artifact: artifactPayload,
            fetched_at: '2026-04-14T00:00:00Z',
        });

        expect(client.getCachedPackForManifest(manifest, licenceScope)?.artifact).toEqual(artifactPayload);
        expect(client.getCachedPackForManifest({ ...manifest, pack_version: 2 }, licenceScope)).toBeUndefined();
        expect(client.getCachedPackForManifest({ ...manifest, sha256: 'changed' }, licenceScope)).toBeUndefined();
    });

    it('rejects a pack when the integrity hash does not match', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);

        (global.fetch as jest.Mock) = jest.fn().mockResolvedValue(createJsonResponse({
            schema_version: 'owlvex.rulepack.artifact.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            issued_at: '2026-04-14T00:00:00Z',
            expires_at: '2026-05-14T00:00:00Z',
            sha256: 'wrong',
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            artifact: { schema_version: 'owlvex.issue-pack.v1' },
        }));

        await expect(client.fetchPackArtifact('https://api.example.test', 'licence-key', {
            schema_version: 'owlvex.rulepack.manifest.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            issued_at: '2026-04-14T00:00:00Z',
            expires_at: '2026-05-14T00:00:00Z',
            sha256: 'wrong',
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            signature_algorithm: 'ed25519',
            key_id: 'owlvex-dev-ed25519-2026-04',
            signature: signManifest({
                schema_version: 'owlvex.rulepack.manifest.v1',
                pack_id: 'owlvex.issue-pack.v1',
                pack_type: 'issue-pack',
                pack_version: 1,
                issued_at: '2026-04-14T00:00:00Z',
                expires_at: '2026-05-14T00:00:00Z',
                sha256: 'wrong',
                size_bytes: 10,
                frameworks: [],
                licence_scope: licenceScope,
                download_path: '/v1/packs/owlvex.issue-pack.v1',
                signature_algorithm: 'ed25519',
                key_id: 'owlvex-dev-ed25519-2026-04',
            }),
        })).rejects.toThrow(/integrity check failed/i);
    });

    it('rejects a manifest when the signature is invalid', async () => {
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
                    issued_at: '2026-04-14T00:00:00Z',
                    expires_at: '2026-05-14T00:00:00Z',
                    sha256: 'abc',
                    size_bytes: 10,
                    frameworks: [],
                    licence_scope: licenceScope,
                    download_path: '/v1/packs/owlvex.issue-pack.v1',
                    signature_algorithm: 'ed25519',
                    key_id: 'owlvex-dev-ed25519-2026-04',
                    signature: 'invalid',
                },
            ],
        }));

        await expect(client.syncManifest('https://api.example.test', 'licence-key'))
            .rejects.toThrow(/signature verification failed/i);
    });

    it('treats stale cached manifest metadata as unavailable by default', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);
        await storage.update('owlvex.rulepacks.manifest', {
            schema_version: 'owlvex.rulepack.manifest-list.v1',
            fetched_at: '2026-04-01T00:00:00Z',
            packs: [{
                schema_version: 'owlvex.rulepack.manifest.v1',
                pack_id: 'owlvex.issue-pack.v1',
                pack_type: 'issue-pack',
                pack_version: 1,
                issued_at: '2026-04-14T00:00:00Z',
                expires_at: '2026-05-14T00:00:00Z',
                sha256: 'abc',
                size_bytes: 10,
                frameworks: [],
                licence_scope: licenceScope,
                download_path: '/v1/packs/owlvex.issue-pack.v1',
                signature_algorithm: 'ed25519',
                key_id: 'owlvex-dev-ed25519-2026-04',
                signature: signManifest({
                    schema_version: 'owlvex.rulepack.manifest.v1',
                    pack_id: 'owlvex.issue-pack.v1',
                    pack_type: 'issue-pack',
                    pack_version: 1,
                    issued_at: '2026-04-14T00:00:00Z',
                    expires_at: '2026-05-14T00:00:00Z',
                    sha256: 'abc',
                    size_bytes: 10,
                    frameworks: [],
                    licence_scope: licenceScope,
                    download_path: '/v1/packs/owlvex.issue-pack.v1',
                    signature_algorithm: 'ed25519',
                    key_id: 'owlvex-dev-ed25519-2026-04',
                }),
            }],
        });

        expect(client.getCachedManifest()).toBeUndefined();
        expect(client.getCachedManifest(undefined, { allowStale: true })?.packs[0].pack_id).toBe('owlvex.issue-pack.v1');
        expect(client.getCachedManifestFreshness()).toBe('stale');
    });

    it('accepts a manifest signed by a newer pinned rotation key', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);
        const unsignedEntry = {
            schema_version: 'owlvex.rulepack.manifest.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 2,
            issued_at: '2026-07-14T00:00:00Z',
            expires_at: '2026-08-14T00:00:00Z',
            sha256: 'def',
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            signature_algorithm: 'ed25519',
            key_id: 'owlvex-next-ed25519-2026-07',
        };

        (global.fetch as jest.Mock) = jest.fn().mockResolvedValue(createJsonResponse({
            schema_version: 'owlvex.rulepack.manifest-list.v1',
            packs: [
                {
                    ...unsignedEntry,
                    signature: signManifest(unsignedEntry, nextPrivateKeyPem),
                },
            ],
        }));

        const manifest = await client.syncManifest('https://api.example.test', 'licence-key');
        expect(manifest.packs[0].key_id).toBe('owlvex-next-ed25519-2026-07');
    });

    it('rejects an expired cached pack', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);
        await storage.update('owlvex.rulepacks.pack.owlvex.issue-pack.v1', {
            schema_version: 'owlvex.rulepack.artifact.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            issued_at: '2026-03-14T00:00:00Z',
            expires_at: '2026-03-15T00:00:00Z',
            sha256: 'abc',
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            signature_algorithm: 'ed25519',
            key_id: 'owlvex-dev-ed25519-2026-04',
            signature: signManifest({
                schema_version: 'owlvex.rulepack.artifact.v1',
                pack_id: 'owlvex.issue-pack.v1',
                pack_type: 'issue-pack',
                pack_version: 1,
                issued_at: '2026-03-14T00:00:00Z',
                expires_at: '2026-03-15T00:00:00Z',
                sha256: 'abc',
                size_bytes: 10,
                frameworks: [],
                licence_scope: licenceScope,
                download_path: '/v1/packs/owlvex.issue-pack.v1',
                signature_algorithm: 'ed25519',
                key_id: 'owlvex-dev-ed25519-2026-04',
            }),
            artifact: { schema_version: 'owlvex.issue-pack.v1' },
        });

        expect(client.getCachedPack('owlvex.issue-pack.v1')).toBeUndefined();
    });

    it('rejects a cached pack when entitlement scope no longer matches', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);
        await storage.update('owlvex.rulepacks.pack.owlvex.issue-pack.v1', {
            schema_version: 'owlvex.rulepack.artifact.v1',
            pack_id: 'owlvex.issue-pack.v1',
            pack_type: 'issue-pack',
            pack_version: 1,
            issued_at: '2026-04-14T00:00:00Z',
            expires_at: '2026-05-14T00:00:00Z',
            sha256: 'abc',
            size_bytes: 10,
            frameworks: [],
            licence_scope: licenceScope,
            download_path: '/v1/packs/owlvex.issue-pack.v1',
            signature_algorithm: 'ed25519',
            key_id: 'owlvex-dev-ed25519-2026-04',
            signature: signManifest({
                schema_version: 'owlvex.rulepack.artifact.v1',
                pack_id: 'owlvex.issue-pack.v1',
                pack_type: 'issue-pack',
                pack_version: 1,
                issued_at: '2026-04-14T00:00:00Z',
                expires_at: '2026-05-14T00:00:00Z',
                sha256: 'abc',
                size_bytes: 10,
                frameworks: [],
                licence_scope: licenceScope,
                download_path: '/v1/packs/owlvex.issue-pack.v1',
                signature_algorithm: 'ed25519',
                key_id: 'owlvex-dev-ed25519-2026-04',
            }),
            artifact: { schema_version: 'owlvex.issue-pack.v1' },
        });

        expect(client.getCachedPack('owlvex.issue-pack.v1', { plan: 'team', frameworks: ['OWASP', 'STRIDE'] })).toBeUndefined();
    });

    it('purges cached manifest and pack artifacts', async () => {
        const storage = createStorage();
        const client = new RulePackClient(storage);

        await storage.update('owlvex.rulepacks.manifest', {
            schema_version: 'owlvex.rulepack.manifest-list.v1',
            packs: [{
                schema_version: 'owlvex.rulepack.manifest.v1',
                pack_id: 'owlvex.issue-pack.v1',
                pack_type: 'issue-pack',
                pack_version: 1,
                issued_at: '2026-04-14T00:00:00Z',
                expires_at: '2026-05-14T00:00:00Z',
                sha256: 'abc',
                size_bytes: 10,
                frameworks: [],
                licence_scope: licenceScope,
                download_path: '/v1/packs/owlvex.issue-pack.v1',
                signature_algorithm: 'ed25519',
                key_id: 'owlvex-dev-ed25519-2026-04',
                signature: signManifest({
                    schema_version: 'owlvex.rulepack.manifest.v1',
                    pack_id: 'owlvex.issue-pack.v1',
                    pack_type: 'issue-pack',
                    pack_version: 1,
                    issued_at: '2026-04-14T00:00:00Z',
                    expires_at: '2026-05-14T00:00:00Z',
                    sha256: 'abc',
                    size_bytes: 10,
                    frameworks: [],
                    licence_scope: licenceScope,
                    download_path: '/v1/packs/owlvex.issue-pack.v1',
                    signature_algorithm: 'ed25519',
                    key_id: 'owlvex-dev-ed25519-2026-04',
                }),
            }],
        });
        await storage.update('owlvex.rulepacks.pack.owlvex.issue-pack.v1', {
            pack_id: 'owlvex.issue-pack.v1',
            artifact: { schema_version: 'owlvex.issue-pack.v1' },
        });

        await client.purgeCachedRulePacks();

        expect(storage.get('owlvex.rulepacks.manifest')).toBeUndefined();
        expect(storage.get('owlvex.rulepacks.pack.owlvex.issue-pack.v1')).toBeUndefined();
    });
});
