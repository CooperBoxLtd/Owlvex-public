import fs from 'node:fs/promises';

import { evaluateFile as evaluateSinkFile } from '../sq004/evaluator.mjs';

// Registry of known non-SQL-safe transformation functions.
// These protect against XSS or other injection classes but not SQL injection.
const HTML_SANITIZERS = ['escapeHtml', 'htmlspecialchars', 'encodeHtml', 'htmlEscape', 'escapeXml'];

// Registry of generic sanitization patterns that are not SQL-safe.
// trim, toLowerCase, and similar character-filtering functions do not prevent SQL injection.
const GENERIC_SANITIZERS = ['sanitize', 'sanitizeInput', 'cleanInput', 'clean', 'validate'];

function detectTransformation(source, parameterized) {
  if (parameterized) {
    return { transformation: 'parameterized', sqlSafe: true };
  }

  for (const fn of HTML_SANITIZERS) {
    if (source.includes(`${fn}(`)) {
      return { transformation: 'html-escape', sqlSafe: false };
    }
  }

  for (const fn of GENERIC_SANITIZERS) {
    const pattern = new RegExp(`\\b${fn}\\s*\\(`);
    if (pattern.test(source)) {
      return { transformation: 'generic', sqlSafe: false };
    }
  }

  return { transformation: 'none', sqlSafe: false };
}

export async function evaluateFile(filePath) {
  const [source, sinkResult] = await Promise.all([
    fs.readFile(filePath, 'utf8'),
    evaluateSinkFile(filePath),
  ]);

  if (!sinkResult.sink) {
    return {
      transformation: 'none',
      sqlSafe: true,
      finding: false,
      type: 'no-query-sink',
      explanation: 'No SQL query sink detected.',
    };
  }

  const { transformation, sqlSafe } = detectTransformation(source, sinkResult.parameterized);

  if (sqlSafe) {
    return {
      transformation,
      sqlSafe,
      finding: false,
      type: 'parameterized-query',
      explanation: 'SQL query uses parameterized binding — no injection risk from transformation.',
    };
  }

  if (transformation === 'html-escape') {
    return {
      transformation,
      sqlSafe,
      finding: true,
      type: 'wrong-sql-transformation',
      explanation: 'An HTML-oriented sanitizer was applied but provides no SQL injection protection.',
    };
  }

  if (transformation === 'generic') {
    return {
      transformation,
      sqlSafe,
      finding: true,
      type: 'wrong-sql-transformation',
      explanation: 'A generic sanitizer was applied but provides no SQL injection protection.',
    };
  }

  return {
    transformation,
    sqlSafe,
    finding: true,
    type: 'no-sql-validation',
    explanation: 'No SQL-safe transformation or parameterized binding was detected.',
  };
}
