import fs from 'node:fs/promises';

import { evaluateFile as evaluateSinkFile } from '../sq004/evaluator.mjs';
import { mergeEnvironments, mergeTrust } from './lattice.mjs';
import { TRUST_STATES } from './types.mjs';

function countBraceBalance(text) {
  return [...text].filter((value) => value === '{').length
    - [...text].filter((value) => value === '}').length;
}

function stripInlineComment(line) {
  const index = line.indexOf('//');
  return index === -1 ? line : line.slice(0, index);
}

function extractHandlerSignature(source) {
  const lines = source.split(/\r?\n/);
  const line = lines.find((entry) => entry.includes('function handler('));
  if (!line) {
    throw new Error('Could not find handler function.');
  }

  const match = line.match(/function\s+handler\(([^)]*)\)/);
  if (!match) {
    throw new Error('Could not parse handler parameters.');
  }

  return match[1].split(',').map((item) => item.trim()).filter(Boolean);
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

function findIfConsequentEnd(lines, startIndex) {
  let balance = countBraceBalance(lines[startIndex]);
  for (let index = startIndex + 1; index < lines.length; index += 1) {
    const line = stripInlineComment(lines[index]);
    if (balance === 1 && line.includes('else')) {
      return index;
    }

    balance += countBraceBalance(line);
    if (balance === 0) {
      return index;
    }
  }

  throw new Error(`Unbalanced if block starting at line ${startIndex + 1}.`);
}

function findElseBlockEnd(lines, elseLineIndex) {
  const line = stripInlineComment(lines[elseLineIndex]);
  const elseIndex = line.indexOf('else');
  let balance = countBraceBalance(line.slice(elseIndex));

  for (let index = elseLineIndex + 1; index < lines.length; index += 1) {
    balance += countBraceBalance(lines[index]);
    if (balance === 0) {
      return index;
    }
  }

  throw new Error(`Unbalanced else block starting at line ${elseLineIndex + 1}.`);
}

function cloneContext(context) {
  return {
    env: new Map(context.env),
  };
}

function splitInterpolations(templateExpression) {
  const matches = [...templateExpression.matchAll(/\$\{([^}]+)\}/g)];
  return matches.map((match) => match[1].trim());
}

function evaluateExpression(expression, context) {
  const trimmed = expression.trim();

  if (
    (trimmed.startsWith('\'') && trimmed.endsWith('\'')) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    return TRUST_STATES.SAFE;
  }

  if (trimmed.startsWith('`') && trimmed.endsWith('`')) {
    const interpolations = splitInterpolations(trimmed);
    if (interpolations.length === 0) {
      return TRUST_STATES.SAFE;
    }

    const mergedInterpolations = interpolations.reduce(
      (state, interpolation) => mergeTrust(state, evaluateExpression(interpolation, context)),
      TRUST_STATES.UNKNOWN,
    );

    return mergedInterpolations === TRUST_STATES.UNKNOWN ? TRUST_STATES.SAFE : mergedInterpolations;
  }

  if (/^\w+$/.test(trimmed)) {
    return context.env.get(trimmed) ?? TRUST_STATES.UNKNOWN;
  }

  return TRUST_STATES.UNKNOWN;
}

function evaluateAssignment(line, context) {
  const declarationMatch = line.match(/^(?:const|let|var)\s+(\w+)\s*=\s*(.+);$/);
  if (declarationMatch) {
    const [, name, expression] = declarationMatch;
    context.env.set(name, evaluateExpression(expression, context));
    return true;
  }

  const declarationWithoutInit = line.match(/^(?:const|let|var)\s+(\w+)\s*;$/);
  if (declarationWithoutInit) {
    const [, name] = declarationWithoutInit;
    context.env.set(name, TRUST_STATES.UNKNOWN);
    return true;
  }

  const assignmentMatch = line.match(/^(\w+)\s*=\s*(.+);$/);
  if (assignmentMatch) {
    const [, name, expression] = assignmentMatch;
    context.env.set(name, evaluateExpression(expression, context));
    return true;
  }

  return false;
}

function evaluateBlock(lines, context) {
  let index = 0;

  while (index < lines.length) {
    const rawLine = lines[index];
    const line = stripInlineComment(rawLine).trim();

    if (!line || line === '}') {
      index += 1;
      continue;
    }

    if (line.startsWith('if ') || line.startsWith('if(')) {
      const thenStart = index;
      const thenEnd = findIfConsequentEnd(lines, thenStart);
      const thenLines = lines.slice(thenStart + 1, thenEnd);
      const thenContext = cloneContext(context);
      evaluateBlock(thenLines, thenContext);

      let elseContext = cloneContext(context);
      let nextIndex = thenEnd + 1;
      while (nextIndex < lines.length && !stripInlineComment(lines[nextIndex]).trim()) {
        nextIndex += 1;
      }

      const sameLineElse = stripInlineComment(lines[thenEnd]).includes('else');
      const elseLineIndex = sameLineElse ? thenEnd : nextIndex;
      const elseLine = lines[elseLineIndex] ? stripInlineComment(lines[elseLineIndex]).trim() : '';

      if (elseLine.includes('else')) {
        const elseEnd = findElseBlockEnd(lines, elseLineIndex);
        const elseLines = lines.slice(elseLineIndex + 1, elseEnd);
        elseContext = cloneContext(context);
        evaluateBlock(elseLines, elseContext);
        index = elseEnd + 1;
      } else {
        index = thenEnd + 1;
      }

      const merged = mergeEnvironments(context.env, thenContext.env, elseContext.env);
      context.env.clear();
      for (const [name, state] of merged.entries()) {
        context.env.set(name, state);
      }
      continue;
    }

    evaluateAssignment(line, context);
    index += 1;
  }
}

export async function evaluateFile(filePath) {
  const [source, sinkResult] = await Promise.all([
    fs.readFile(filePath, 'utf8'),
    evaluateSinkFile(filePath),
  ]);
  const params = extractHandlerSignature(source);
  const handlerLines = extractHandlerLines(source);
  const context = { env: new Map() };

  for (const param of params) {
    if (param === 'db' || /^is[A-Z]/.test(param) || param === 'flag') {
      context.env.set(param, TRUST_STATES.UNKNOWN);
      continue;
    }

    context.env.set(param, TRUST_STATES.UNSAFE);
  }

  evaluateBlock(handlerLines, context);

  const queryVariable = /^[A-Za-z_]\w*$/.test(sinkResult.queryExpression ?? '')
    ? sinkResult.queryExpression
    : null;
  const trustStateAtSink = queryVariable
    ? (context.env.get(queryVariable) ?? TRUST_STATES.UNKNOWN)
    : evaluateExpression(sinkResult.queryExpression ?? '', context);

  return {
    states: Object.fromEntries(context.env.entries()),
    queryVariable,
    trustStateAtSink,
    parameterized: sinkResult.parameterized,
    sink: sinkResult.sink,
    sinkKind: sinkResult.sinkKind,
    queryExpression: sinkResult.queryExpression,
  };
}
