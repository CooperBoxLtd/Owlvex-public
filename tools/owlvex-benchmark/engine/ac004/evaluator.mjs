/**
 * AC-004: Resource Shape
 *
 * Classifies how the handler accesses resources in the data store.
 * Determines whether the query is scoped to the current user's resources
 * (OWNED), uses a caller-supplied arbitrary identifier (ARBITRARY), or
 * accesses a static constant resource (CONSTANT).
 *
 * OWNED:    query args include currentUser.id / user.id (session-bound)
 * ARBITRARY: query args include a variable (caller-supplied ID)
 * CONSTANT:  query args include only string/numeric literals
 */

import fs from 'node:fs/promises';

// Session-bound expressions that scope a query to the current user.
const SESSION_ID_PATTERN = /\b(currentUser|user|authUser|me|session|principal)\.(id|userId)\b/;

// String or numeric literal pattern.
const LITERAL_PATTERN = /^(['"`])[^]*\1$|^\d+$/;

function stripInlineComment(line) {
  const index = line.indexOf('//');
  return index === -1 ? line : line.slice(0, index);
}

function countBraceBalance(text) {
  return [...text].filter((ch) => ch === '{').length
    - [...text].filter((ch) => ch === '}').length;
}

function extractHandlerLines(source) {
  const lines = source.split(/\r?\n/);
  const startIndex = lines.findIndex((line) => line.includes('function handler('));
  if (startIndex === -1) {
    throw new Error('Could not find handler function.');
  }

  let balance = countBraceBalance(lines[startIndex]);
  const blockLines = [];

  for (let index = startIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    balance += countBraceBalance(line);
    if (balance >= 0) {
      blockLines.push(line);
    }
    if (balance === 0) {
      blockLines.pop();
      break;
    }
  }

  return blockLines;
}

function parseQueryArgs(argsText) {
  if (!argsText || !argsText.trim()) return [];
  // Split on commas, respecting nested brackets/parens.
  const args = [];
  let current = '';
  let depth = 0;
  let quote = null;

  for (const char of argsText) {
    if (quote) {
      current += char;
      if (char === quote) quote = null;
      continue;
    }
    if (char === '\'' || char === '"' || char === '`') {
      quote = char;
      current += char;
      continue;
    }
    if (char === '(' || char === '[' || char === '{') { depth += 1; current += char; continue; }
    if (char === ')' || char === ']' || char === '}') { depth -= 1; current += char; continue; }
    if (char === ',' && depth === 0) {
      args.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim()) args.push(current.trim());
  return args;
}

function classifyQueryArgs(argsText) {
  if (!argsText) return 'UNKNOWN';

  // Strip surrounding brackets if present.
  const inner = argsText.trim().replace(/^\[/, '').replace(/\]$/, '');
  const args = parseQueryArgs(inner);

  if (args.length === 0) return 'UNKNOWN';

  // If any arg is a session-bound expression → OWNED.
  if (args.some((arg) => SESSION_ID_PATTERN.test(arg))) return 'OWNED';

  // If all args are literals → CONSTANT.
  if (args.every((arg) => LITERAL_PATTERN.test(arg))) return 'CONSTANT';

  // Otherwise: contains a variable (caller-supplied) → ARBITRARY.
  return 'ARBITRARY';
}

function extractQueryCall(line) {
  // Match: db.query('...', [...]) or db.query('...')
  const match = line.match(/\bdb\.query\s*\(\s*(['"`][^]*?['"`])\s*(?:,\s*(\[[^\]]*\]))?\s*\)/);
  if (!match) return null;
  return {
    sink: 'db.query',
    queryText: match[1],
    argsText: match[2] ?? null,
  };
}

export async function evaluateFile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const handlerLines = extractHandlerLines(source);

  for (const rawLine of handlerLines) {
    const line = stripInlineComment(rawLine).trim();
    if (!line) continue;

    const queryCall = extractQueryCall(line);
    if (queryCall) {
      const resourceShape = classifyQueryArgs(queryCall.argsText);
      return {
        sink: queryCall.sink,
        queryText: queryCall.queryText,
        queryArgs: queryCall.argsText,
        resourceShape,
        finding: resourceShape === 'ARBITRARY',
      };
    }
  }

  return {
    sink: null,
    queryText: null,
    queryArgs: null,
    resourceShape: 'UNKNOWN',
    finding: false,
  };
}
