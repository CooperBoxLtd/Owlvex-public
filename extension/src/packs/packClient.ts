import * as crypto from 'crypto';
import type * as vscode from 'vscode';

export interface PackManifestEntry {
    schema_version: string;
    pack_id: string;
    pack_type: string;
    pack_version: number | string;
    sha256: string;
    size_bytes: number;
    frameworks: string[];
    download_path: string;
}

export interface PackManifestList {
    schema_version: string;
    packs: PackManifestEntry[];
    fetched_at?: string;
}

export interface PackArtifactResponse extends PackManifestEntry {
    artifact: Record<string, unknown>;
}

const MANIFEST_CACHE_KEY = 'owlvex.rulepacks.manifest';
const PACK_CACHE_KEY_PREFIX = 'owlvex.rulepacks.pack';

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

export class RulePackClient {
    constructor(private readonly storage: vscode.Memento) {}

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
        const cachedManifest: PackManifestList = {
            ...manifest,
            fetched_at: new Date().toISOString(),
        };
        await this.storage.update(MANIFEST_CACHE_KEY, cachedManifest);
        return cachedManifest;
    }

    getCachedManifest(): PackManifestList | undefined {
        return this.storage.get<PackManifestList>(MANIFEST_CACHE_KEY);
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

        await this.storage.update(`${PACK_CACHE_KEY_PREFIX}.${manifest.pack_id}`, artifact);
        return artifact;
    }

    getCachedPack(packId: string): PackArtifactResponse | undefined {
        return this.storage.get<PackArtifactResponse>(`${PACK_CACHE_KEY_PREFIX}.${packId}`);
    }
}
