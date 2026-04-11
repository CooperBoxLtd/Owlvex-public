// scanner.cjs — CJS bridge so esbuild can statically bundle the scanner
// esbuild resolves this file and inlines the DeterministicScanner class.
'use strict';
module.exports = require('../extension/out/scanner/deterministicScanner.js');
