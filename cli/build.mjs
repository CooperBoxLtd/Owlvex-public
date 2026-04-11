/**
 * build.mjs — bundles the Owlvex CLI into a single self-contained file
 *
 * Output: dist/owlvex.mjs (~38KB, no install required)
 * Run:    node build.mjs
 */

import { build } from 'esbuild';
import { mkdirSync } from 'fs';

mkdirSync('dist', { recursive: true });

await build({
    entryPoints: ['owlvex.mjs'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile: 'dist/owlvex.mjs',
    // Inject a real require() so bundled CJS modules can load Node built-ins
    // (crypto, fs, path) at runtime — esbuild's default CJS shim doesn't do this.
    banner: {
        js: [
            '#!/usr/bin/env node',
            "import { createRequire as __cjsRequire } from 'module';",
            'const require = __cjsRequire(import.meta.url);',
        ].join('\n'),
    },
});

console.log('Built dist/owlvex.mjs');
