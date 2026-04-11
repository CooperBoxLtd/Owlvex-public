/**
 * SM-002 Evaluator — Debug Mode Without Environment Guard
 *
 * ConditionalRule contract:
 *   cheap gate  → source contains deployment-env signals (NODE_ENV, process.env, …)
 *   structural  → app.set('debug', true) / app.enable('debug') is NOT inside
 *                 an immediately enclosing block whose condition includes
 *                 NODE_ENV !== 'production'
 *   output      → { finding, has_env_context, has_debug_activation, is_guarded }
 */

import fs from 'node:fs/promises';

// --- Gate -------------------------------------------------------------------

const ENV_SIGNALS = ['NODE_ENV', 'process.env', 'APP_ENV', 'isProduction', 'isProd'];

function hasEnvContext(source) {
  return ENV_SIGNALS.some((s) => source.includes(s));
}

// --- Structural check -------------------------------------------------------

const DEBUG_ACTIVATION_RE =
  /\bapp\s*\.\s*(?:set\s*\(\s*['"]debug['"]\s*,\s*true\s*\)|enable\s*\(\s*['"]debug['"]\s*\))/g;

const ENV_GUARD_CONDITION_RE =
  /\b(?:NODE_ENV|APP_ENV)\s*(?:!==?|===?)\s*['"](?:production|prod)['"]/;

/**
 * Strips block and line comments (length-preserving, newlines kept).
 * Used for PATTERN MATCHING — string literals in code are preserved so that
 * patterns like `app.set('debug', true)` can still be found.
 */
function stripComments(source) {
  let result = source.replace(/\/\*[\s\S]*?\*\//g,
    (m) => m.split('').map((c) => (c === '\n' ? '\n' : ' ')).join(''));
  result = result.replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));
  return result;
}

/**
 * Strips single- and double-quoted string literals (length-preserving).
 * Apply AFTER `stripComments`. Used for BRACE DEPTH TRACKING in `isInsideEnvGuard`
 * so that `{` / `}` inside string values cannot confuse the depth counter.
 */
function stripQuotedStrings(source) {
  return source.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, (m) => ' '.repeat(m.length));
}

/**
 * Returns true when `matchIndex` lies inside a block whose opening `{` is
 * immediately preceded by an env guard condition.
 */
function isInsideEnvGuard(source, strippedSource, matchIndex) {
  let depth = 0;
  for (let i = matchIndex - 1; i >= 0; i--) {
    const ch = strippedSource[i];
    if (ch === '}') {
      depth++;
    } else if (ch === '{') {
      if (depth === 0) {
        const before = source.slice(Math.max(0, i - 300), i);
        return ENV_GUARD_CONDITION_RE.test(before);
      }
      depth--;
    }
  }
  return false;
}

// --- Public API -------------------------------------------------------------

export async function evaluateFile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');

  if (!hasEnvContext(source)) {
    return {
      hasEnvContext: false,
      hasDebugActivation: false,
      isGuarded: false,
      finding: false,
    };
  }

  const strippedComments = stripComments(source);
  const strippedFull = stripQuotedStrings(strippedComments);
  const pattern = new RegExp(DEBUG_ACTIVATION_RE.source, DEBUG_ACTIVATION_RE.flags);
  let match;

  while ((match = pattern.exec(strippedComments)) !== null) {
    if (!isInsideEnvGuard(source, strippedFull, match.index)) {
      return {
        hasEnvContext: true,
        hasDebugActivation: true,
        isGuarded: false,
        finding: true,
      };
    }
  }

  // Re-test using stripped-comments source for activation presence reporting.
  const hadActivation = new RegExp(DEBUG_ACTIVATION_RE.source).test(strippedComments);

  return {
    hasEnvContext: true,
    hasDebugActivation: hadActivation,
    isGuarded: hadActivation,
    finding: false,
  };
}
