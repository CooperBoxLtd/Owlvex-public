import fs from 'node:fs/promises';

import { mergeEnvironments } from './lattice.mjs';
import { TRUST_STATES } from './types.mjs';

const SANITIZERS = {
  sanitize: 'generic',
  escapeShellArg: 'shell',
  validateInput: 'generic',
  escapeHtml: 'html',
};

function makeTransformationMetadata(
  transformation = 'none',
  sanitizer = null,
  context = null,
) {
  return {
    transformation,
    sanitizer,
    context,
  };
}

function makeEvalResult(
  trustState,
  transformation = 'none',
  sanitizer = null,
  context = null,
) {
  return {
    trustState,
    transformation,
    sanitizer,
    context,
  };
}

function cloneContext(context) {
  return {
    env: new Map(context.env),
    transformations: new Map(context.transformations),
  };
}

function countChar(text, char) {
  return [...text].filter((value) => value === char).length;
}

function countBraceBalance(text) {
  return countChar(text, '{') - countChar(text, '}');
}

function stripInlineComment(line) {
  const index = line.indexOf('//');
  return index === -1 ? line : line.slice(0, index);
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

    if (balance < 0) {
      break;
    }

    if (balance === -1) {
      break;
    }

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

function findBlockEnd(lines, startIndex) {
  let balance = countBraceBalance(lines[startIndex]);
  for (let index = startIndex + 1; index < lines.length; index += 1) {
    balance += countBraceBalance(lines[index]);
    if (balance === 0) {
      return index;
    }
  }

  throw new Error(`Unbalanced block starting at line ${startIndex + 1}.`);
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
  if (elseIndex === -1) {
    throw new Error(`Expected else block at line ${elseLineIndex + 1}.`);
  }

  let balance = countBraceBalance(line.slice(elseIndex));
  for (let index = elseLineIndex + 1; index < lines.length; index += 1) {
    balance += countBraceBalance(lines[index]);
    if (balance === 0) {
      return index;
    }
  }

  throw new Error(`Unbalanced else block starting at line ${elseLineIndex + 1}.`);
}

function evaluateExpression(expression, context) {
  const trimmed = expression.trim();
  const env = context.env;

  if (
    (trimmed.startsWith('\'') && trimmed.endsWith('\'')) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith('`') && trimmed.endsWith('`'))
  ) {
    return makeEvalResult(TRUST_STATES.SAFE);
  }

  if (/^req\.query\.\w+$/.test(trimmed)) {
    return makeEvalResult(TRUST_STATES.UNSAFE);
  }

  const callMatch = trimmed.match(/^(\w+)\((.+)\)$/);
  if (callMatch) {
    const [, callee, innerExpression] = callMatch;
    if (callee in SANITIZERS) {
      const inputResult = evaluateExpression(innerExpression, context);
      const sanitizerContext = SANITIZERS[callee];
      if (inputResult.trustState === TRUST_STATES.UNSAFE || inputResult.trustState === TRUST_STATES.MIXED) {
        return makeEvalResult(TRUST_STATES.SAFE, 'sanitized', callee, sanitizerContext);
      }

      return makeEvalResult(inputResult.trustState, 'sanitized', callee, sanitizerContext);
    }

    return makeEvalResult(TRUST_STATES.UNKNOWN);
  }

  if (/^\w+$/.test(trimmed)) {
    const metadata = context.transformations.get(trimmed) ?? makeTransformationMetadata();
    return makeEvalResult(
      env.get(trimmed) ?? TRUST_STATES.UNKNOWN,
      metadata.transformation,
      metadata.sanitizer,
      metadata.context,
    );
  }

  return makeEvalResult(TRUST_STATES.UNKNOWN);
}

function evaluateAssignment(line, context) {
  const declarationMatch = line.match(/^(?:const|let|var)\s+(\w+)\s*=\s*(.+);$/);
  if (declarationMatch) {
    const [, name, expression] = declarationMatch;
    const result = evaluateExpression(expression, context);
    context.env.set(name, result.trustState);
    context.transformations.set(
      name,
      makeTransformationMetadata(result.transformation, result.sanitizer, result.context),
    );
    return true;
  }

  const declarationWithoutInit = line.match(/^(?:const|let|var)\s+(\w+)\s*;$/);
  if (declarationWithoutInit) {
    const [, name] = declarationWithoutInit;
    context.env.set(name, TRUST_STATES.UNKNOWN);
    context.transformations.set(name, makeTransformationMetadata());
    return true;
  }

  const assignmentMatch = line.match(/^(\w+)\s*=\s*(.+);$/);
  if (assignmentMatch) {
    const [, name, expression] = assignmentMatch;
    const result = evaluateExpression(expression, context);
    context.env.set(name, result.trustState);
    context.transformations.set(
      name,
      makeTransformationMetadata(result.transformation, result.sanitizer, result.context),
    );
    return true;
  }

  return false;
}

function evaluateBlock(lines, context, findings) {
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
      evaluateBlock(thenLines, thenContext, findings);

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
        evaluateBlock(elseLines, elseContext, findings);
        index = elseEnd + 1;
      } else {
        index = thenEnd + 1;
      }

      const merged = mergeEnvironments(context.env, thenContext.env, elseContext.env);
      const baseTransformations = new Map(context.transformations);
      context.env.clear();
      for (const [name, state] of merged.entries()) {
        context.env.set(name, state);
      }

      const names = new Set([
        ...context.transformations.keys(),
        ...thenContext.transformations.keys(),
        ...elseContext.transformations.keys(),
      ]);
      context.transformations.clear();
      for (const name of names) {
        const left = thenContext.transformations.get(name)
          ?? baseTransformations.get(name)
          ?? makeTransformationMetadata();
        const right = elseContext.transformations.get(name)
          ?? baseTransformations.get(name)
          ?? makeTransformationMetadata();

        if (
          left.transformation === right.transformation
          && left.sanitizer === right.sanitizer
          && left.context === right.context
        ) {
          context.transformations.set(name, left);
          continue;
        }

        if (left.transformation === 'sanitized' && right.transformation === 'sanitized') {
          context.transformations.set(name, makeTransformationMetadata('sanitized'));
          continue;
        }

        if (left.transformation === 'sanitized' || right.transformation === 'sanitized') {
          context.transformations.set(name, makeTransformationMetadata('sanitized'));
          continue;
        }

        context.transformations.set(name, makeTransformationMetadata());
      }
      continue;
    }

    const execMatch = line.match(/^exec\((.+)\);$/);
    if (execMatch) {
      const expression = execMatch[1].trim();
      const variable = /^\w+$/.test(expression) ? expression : null;
      const metadata = variable
        ? (context.transformations.get(variable) ?? makeTransformationMetadata())
        : null;
      const expressionResult = variable
        ? {
            trustState: context.env.get(variable) ?? TRUST_STATES.UNKNOWN,
            transformation: metadata.transformation,
            sanitizer: metadata.sanitizer,
            context: metadata.context,
          }
        : evaluateExpression(expression, context);
      findings.push({
        sink: 'exec',
        expression,
        variable,
        trustState: expressionResult.trustState,
        transformation: expressionResult.transformation,
        sanitizer: expressionResult.sanitizer,
        transformationContext: expressionResult.context,
      });
      index += 1;
      continue;
    }

    evaluateAssignment(line, context);
    index += 1;
  }
}

export async function evaluateFile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const handlerLines = extractHandlerLines(source);
  const context = {
    env: new Map(),
    transformations: new Map(),
  };
  const findings = [];

  evaluateBlock(handlerLines, context, findings);

  const primaryFinding = findings.at(-1) ?? null;
  return {
    states: Object.fromEntries(context.env.entries()),
    transformations: Object.fromEntries(
      [...context.transformations.entries()].map(([name, metadata]) => [name, metadata.transformation]),
    ),
    transformationMetadata: Object.fromEntries(context.transformations.entries()),
    findings,
    primaryFinding,
  };
}
