/**
 * AC-003: Policy Check
 *
 * Scans the handler body for authorization patterns and classifies what kind
 * of access control policy (if any) is present.
 *
 * Policy check types (in priority order — highest first):
 *   EXPLICIT   — authorize(), hasPermission(), canAccess(), authz()
 *   OWNERSHIP  — ownership comparison (.userId, .ownerId) vs currentUser.id
 *   ROLE       — isAdmin(), hasRole(), checkRole(), requireRole()
 *   AUTH_ONLY  — isAuthenticated(), requireAuth(), checkAuth()
 *   MISSING    — no authorization pattern found
 *
 * Finding: true when policyCheck is MISSING or AUTH_ONLY (insufficient).
 */

import fs from 'node:fs/promises';

// EXPLICIT: calls that perform full permission/authorization check.
const EXPLICIT_PATTERN = /\b(authorize|hasPermission|canAccess|authz|checkPermission|requirePermission)\s*\(/;

// OWNERSHIP: comparing a resource property to the current user's ID.
const OWNERSHIP_PATTERN = /\.(userId|ownerId|createdBy|owner|authorId)\b.*(?:!==|===|!=|==).*(?:currentUser|user|me)\.(id|userId)|(?:currentUser|user|me)\.(id|userId).*(?:!==|===|!=|==).*\.(userId|ownerId|createdBy|owner|authorId)/;

// ROLE: role-based access checks.
const ROLE_PATTERN = /\b(isAdmin|hasRole|checkRole|requireRole|hasAnyRole|checkAccess)\s*\(/;

// AUTH_ONLY: authentication-only checks (insufficient for object-level authorization).
const AUTH_ONLY_PATTERN = /\b(isAuthenticated|requireAuth|checkAuth|ensureAuth|verifyAuth|authenticated)\s*\(/;

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

export async function evaluateFile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const handlerLines = extractHandlerLines(source);
  const body = handlerLines.map((line) => stripInlineComment(line)).join('\n');

  // Evaluate in priority order — highest wins.
  if (EXPLICIT_PATTERN.test(body)) {
    return { policyCheck: 'EXPLICIT', finding: false };
  }

  if (OWNERSHIP_PATTERN.test(body)) {
    return { policyCheck: 'OWNERSHIP', finding: false };
  }

  if (ROLE_PATTERN.test(body)) {
    return { policyCheck: 'ROLE', finding: false };
  }

  if (AUTH_ONLY_PATTERN.test(body)) {
    return { policyCheck: 'AUTH_ONLY', finding: true };
  }

  return { policyCheck: 'MISSING', finding: true };
}
