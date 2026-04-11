import fs from 'node:fs/promises';

import { evaluateFile as evaluateSinkFile } from '../sq004/evaluator.mjs';
import { evaluateFile as evaluateTrustFile } from '../sq002/evaluator.mjs';

function stripInlineComment(line) {
  const index = line.indexOf('//');
  return index === -1 ? line : line.slice(0, index);
}

function countBraceBalance(text) {
  return [...text].filter((value) => value === '{').length
    - [...text].filter((value) => value === '}').length;
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

function findQueryDefinition(handlerLines, name) {
  for (const rawLine of handlerLines) {
    const line = stripInlineComment(rawLine).trim();
    const match = line.match(new RegExp(`^(?:const|let|var)\\s+${name}\\s*=\\s*(.+);$`));
    if (match) {
      return match[1].trim();
    }
  }

  return null;
}

function classifyQuerySource(queryExpression, queryDefinition, source, viaWrapper) {
  const expression = queryDefinition ?? queryExpression ?? '';

  if (!expression) {
    return {
      finding: false,
      type: 'unknown-query-shape',
      explanation: 'No SQL query shape was detected.',
    };
  }

  if (viaWrapper) {
    return {
      finding: true,
      type: 'wrapped-sql-sink',
      explanation: 'A wrapped SQL sink still receives interpolated query text.',
    };
  }

  if (/escapeHtml\s*\(/.test(source) && /SELECT|INSERT|UPDATE|DELETE/i.test(expression)) {
    return {
      finding: true,
      type: 'context-mismatch-query',
      explanation: 'A non-SQL transformation is reused in SQL query construction.',
    };
  }

  if (/if\s*\(/.test(source) && /`[^`]*\$\{[^}]+\}[^`]*`/.test(expression)) {
    return {
      finding: true,
      type: 'mixed-query-trust',
      explanation: 'Branch-dependent data still reaches interpolated SQL query text.',
    };
  }

  if (/`[^`]*\$\{[^}]+\}[^`]*`/.test(expression)) {
    return {
      finding: true,
      type: 'sql-injection',
      explanation: 'Interpolated SQL query text reaches a database query sink.',
    };
  }

  return {
    finding: false,
    type: 'parameterized-query',
    explanation: 'SQL query text is not interpolated and input is expected to be bound separately.',
  };
}

export async function evaluateFile(filePath) {
  const [source, sinkResult, trustResult] = await Promise.all([
    fs.readFile(filePath, 'utf8'),
    evaluateSinkFile(filePath),
    evaluateTrustFile(filePath),
  ]);

  if (!sinkResult.sink) {
    return {
      sink: null,
      sinkKind: null,
      parameterized: false,
      queryExpression: null,
      queryDefinition: null,
      finding: false,
      type: 'no-query-sink',
      explanation: 'No SQL query sink detected.',
    };
  }

  const handlerLines = extractHandlerLines(source);
  const queryDefinition = /^[A-Za-z_]\w*$/.test(sinkResult.queryExpression ?? '')
    ? findQueryDefinition(handlerLines, sinkResult.queryExpression)
    : sinkResult.queryExpression;

  if (sinkResult.parameterized) {
    return {
      ...sinkResult,
      queryDefinition,
      trustStateAtSink: trustResult.trustStateAtSink,
      finding: false,
      type: 'parameterized-query',
      explanation: 'SQL query text is constant and user input is bound through parameters.',
    };
  }

  const classification = classifyQuerySource(
    sinkResult.queryExpression,
    queryDefinition,
    source,
    sinkResult.viaWrapper,
  );

  return {
    ...sinkResult,
    queryDefinition,
    trustStateAtSink: trustResult.trustStateAtSink,
    ...classification,
  };
}
