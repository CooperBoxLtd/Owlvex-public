import * as crypto from 'crypto';
import type * as vscode from 'vscode';

const OWLVEX_PACK_SIGNING_PUBLIC_KEYS: Record<string, string> = {
    'owlvex-dev-ed25519-2026-04': `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEABJfLXYgBnSn0emL1re4+xOQL3iW9n8KDn8AGf32fm+g=
-----END PUBLIC KEY-----`,
    'owlvex-next-ed25519-2026-07': `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADKqdyaXSV5DkTdyZJYeYRPULwlzc3Mquadzrx+VEWew=
-----END PUBLIC KEY-----`,
};

export interface PackManifestEntry {
    schema_version: string;
    pack_id: string;
    pack_type: string;
    pack_version: number | string;
    issued_at: string;
    expires_at: string;
    sha256: string;
    size_bytes: number;
    frameworks: string[];
    licence_scope: {
        plan: string;
        frameworks: string[];
    };
    download_path: string;
    signature_algorithm: string;
    key_id: string;
    signature: string;
}

export interface PackManifestList {
    schema_version: string;
    packs: PackManifestEntry[];
    fetched_at?: string;
}

export interface PackArtifactResponse extends PackManifestEntry {
    artifact: Record<string, unknown>;
    fetched_at?: string;
}

const MANIFEST_CACHE_KEY = 'owlvex.rulepacks.manifest';
const PACK_CACHE_KEY_PREFIX = 'owlvex.rulepacks.pack';
const MANIFEST_MAX_AGE_MS = 6 * 60 * 60 * 1000;

export interface PackEntitlement {
    plan: string;
    frameworks: string[];
}

interface CachedManifestOptions {
    allowStale?: boolean;
}

function stableStringify(value: unknown): string {
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
}

function sha256OfArtifact(artifact: Record<string, unknown>): string {
    return crypto.createHash('sha256').update(stableStringify(artifact)).digest('hex');
}

function manifestSigningPayload(manifest: PackManifestEntry): Omit<PackManifestEntry, 'signature'> {
    return {
        schema_version: manifest.schema_version,
        pack_id: manifest.pack_id,
        pack_type: manifest.pack_type,
        pack_version: manifest.pack_version,
        issued_at: manifest.issued_at,
        expires_at: manifest.expires_at,
        sha256: manifest.sha256,
        size_bytes: manifest.size_bytes,
        frameworks: manifest.frameworks,
        licence_scope: manifest.licence_scope,
        download_path: manifest.download_path,
        signature_algorithm: manifest.signature_algorithm,
        key_id: manifest.key_id,
    };
}

function verifyManifestSignature(manifest: PackManifestEntry): boolean {
    if (manifest.signature_algorithm !== 'ed25519') {
        return false;
    }

    const publicKeyPem = OWLVEX_PACK_SIGNING_PUBLIC_KEYS[manifest.key_id];
    if (!publicKeyPem) {
        return false;
    }

    return crypto.verify(
        null,
        Buffer.from(stableStringify(manifestSigningPayload(manifest))),
        publicKeyPem,
        Buffer.from(manifest.signature, 'base64'),
    );
}

function normalizeFrameworks(frameworks: string[]): string[] {
    return [...new Set(frameworks.map(value => value.trim().toUpperCase()).filter(Boolean))].sort();
}

function entitlementMatches(scope: PackManifestEntry['licence_scope'], entitlement?: PackEntitlement): boolean {
    if (!entitlement) {
        return true;
    }

    return scope.plan === entitlement.plan
        && JSON.stringify(normalizeFrameworks(scope.frameworks)) === JSON.stringify(normalizeFrameworks(entitlement.frameworks));
}

function isNotExpired(expiresAt: string, now = Date.now()): boolean {
    const expiry = Date.parse(expiresAt);
    return Number.isFinite(expiry) && expiry > now;
}

function isManifestFresh(fetchedAt?: string, now = Date.now()): boolean {
    if (!fetchedAt) {
        return false;
    }

    const fetched = Date.parse(fetchedAt);
    return Number.isFinite(fetched) && (now - fetched) <= MANIFEST_MAX_AGE_MS;
}

export class RulePackClient {
    constructor(private readonly storage: vscode.Memento) {}

    private getKnownPackCacheKeys(): string[] {
        const keysFromStorage = Array.isArray((this.storage as any).keys)
            ? (this.storage as any).keys.filter((key: string) => key.startsWith(`${PACK_CACHE_KEY_PREFIX}.`))
            : [];
        const keysFromManifest = this.storage
            .get<PackManifestList>(MANIFEST_CACHE_KEY)?.packs
            .map(pack => `${PACK_CACHE_KEY_PREFIX}.${pack.pack_id}`) ?? [];

        return [...new Set([...keysFromStorage, ...keysFromManifest])];
    }

    async syncManifest(apiUrl: string, licenceKey: string): Promise<PackManifestList> {
        const res = await fetch(`${apiUrl}/v1/packs/manifest`, {
            headers: {
                'X-Licence-Key': licenceKey,
            },
        });

        if (!res.ok) {
            throw new Error(`Failed to fetch rule pack manifest (HTTP ${res.status})`);
        }

        const manifest = await res.json() as PackManifestList;
        for (const entry of manifest.packs) {
            if (!verifyManifestSignature(entry)) {
                throw new Error(`Manifest signature verification failed for ${entry.pack_id}`);
            }
        }
        const cachedManifest: PackManifestList = {
            ...manifest,
            fetched_at: new Date().toISOString(),
        };
        await this.storage.update(MANIFEST_CACHE_KEY, cachedManifest);
        return cachedManifest;
    }

    getCachedManifest(entitlement?: PackEntitlement, options: CachedManifestOptions = {}): PackManifestList | undefined {
        const cached = this.storage.get<PackManifestList>(MANIFEST_CACHE_KEY);
        if (!cached) {
            return undefined;
        }

        const freshEnough = isManifestFresh(cached.fetched_at);
        if (!freshEnough && !options.allowStale) {
            return undefined;
        }

        const usablePacks = cached.packs.filter(entry =>
            verifyManifestSignature(entry)
            && isNotExpired(entry.expires_at)
            && entitlementMatches(entry.licence_scope, entitlement),
        );

        return usablePacks.length
            ? { ...cached, packs: usablePacks }
            : undefined;
    }

    getCachedManifestFreshness(entitlement?: PackEntitlement): 'fresh' | 'stale' | 'missing' {
        const cached = this.getCachedManifest(entitlement, { allowStale: true });
        if (!cached) {
            return 'missing';
        }

        return isManifestFresh(cached.fetched_at) ? 'fresh' : 'stale';
    }

    async fetchPackArtifact(apiUrl: string, licenceKey: string, manifest: PackManifestEntry): Promise<PackArtifactResponse> {
        const res = await fetch(`${apiUrl}${manifest.download_path}`, {
            headers: {
                'X-Licence-Key': licenceKey,
            },
        });

        if (!res.ok) {
            throw new Error(`Failed to fetch pack ${manifest.pack_id} (HTTP ${res.status})`);
        }

        const artifact = await res.json() as PackArtifactResponse;
        const computedHash = sha256OfArtifact(artifact.artifact);
        if (computedHash !== manifest.sha256) {
            throw new Error(`Pack integrity check failed for ${manifest.pack_id}`);
        }

        const cachedArtifact: PackArtifactResponse = {
            ...artifact,
            fetched_at: new Date().toISOString(),
        };
        await this.storage.update(`${PACK_CACHE_KEY_PREFIX}.${manifest.pack_id}`, cachedArtifact);
        return cachedArtifact;
    }

    getCachedPack(packId: string, entitlement?: PackEntitlement): PackArtifactResponse | undefined {
        const cached = this.storage.get<PackArtifactResponse>(`${PACK_CACHE_KEY_PREFIX}.${packId}`);
        if (!cached) {
            return undefined;
        }

        const computedHash = sha256OfArtifact(cached.artifact);
        if (computedHash !== cached.sha256 || !isNotExpired(cached.expires_at) || !entitlementMatches(cached.licence_scope, entitlement)) {
            return undefined;
        }

        return cached;
    }

    getCachedPackForManifest(manifest: PackManifestEntry, entitlement?: PackEntitlement): PackArtifactResponse | undefined {
        const cached = this.getCachedPack(manifest.pack_id, entitlement);
        if (!cached) {
            return undefined;
        }

        if (
            cached.pack_version !== manifest.pack_version
            || cached.pack_type !== manifest.pack_type
            || cached.sha256 !== manifest.sha256
            || cached.download_path !== manifest.download_path
        ) {
            return undefined;
        }

        return cached;
    }

    async purgeCachedRulePacks(): Promise<void> {
        await this.storage.update(MANIFEST_CACHE_KEY, undefined);

        for (const key of this.getKnownPackCacheKeys()) {
            await this.storage.update(key, undefined);
        }
    }
}
