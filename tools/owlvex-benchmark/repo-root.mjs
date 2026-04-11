import path from 'node:path';
import { fileURLToPath } from 'node:url';

const toolRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(toolRoot, '..', '..');
const extensionRoot = path.join(repoRoot, 'extension');

export { extensionRoot, repoRoot, toolRoot };
