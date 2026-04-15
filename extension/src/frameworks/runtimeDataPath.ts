import * as fs from 'node:fs';
import * as path from 'node:path';

export function resolveRuntimeDataPath(dirname: string, ...segments: string[]): string {
    const candidates = [
        path.resolve(dirname, '../../data', ...segments),
        path.resolve(dirname, '../../../docs', ...segments),
    ];

    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }

    return candidates[0];
}
