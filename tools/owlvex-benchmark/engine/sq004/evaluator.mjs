import fs from 'node:fs/promises';

function stripInlineComment(line) {
  const index = line.indexOf('//');
  return index === -1 ? line : line.slice(0, index);
}

function splitTopLevelArgs(input) {
  const result = [];
  let current = '';
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  let quote = null;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    const prev = input[index - 1];

    if (quote) {
      current += char;
      if (char === quote && prev !== '\\') {
        quote = null;
      }
      continue;
    }

    if (char === '\'' || char === '"' || char === '`') {
      quote = char;
      current += char;
      continue;
    }

    if (char === '(') paren += 1;
    if (char === ')') paren -= 1;
    if (char === '[') bracket += 1;
    if (char === ']') bracket -= 1;
    if (char === '{') brace += 1;
    if (char === '}') brace -= 1;

    if (char === ',' && paren === 0 && bracket === 0 && brace === 0) {
      result.push(current.trim());
      current = '';
      continue;
    }

    current += char;
  }

  if (current.trim()) {
    result.push(current.trim());
  }

  return result;
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

function buildWrapperMap(source) {
  const wrappers = new Map();
  const wrapperRegex = /function\s+(\w+)\(([^)]*)\)\s*\{([\s\S]*?)\}/g;
  let match;

  while ((match = wrapperRegex.exec(source)) !== null) {
    const [, name, paramsText, body] = match;
    if (name === 'handler') {
      continue;
    }

    const params = paramsText.split(',').map((item) => item.trim()).filter(Boolean);
    const line = body.split(/\r?\n/).map((item) => stripInlineComment(item).trim()).find(Boolean);
    const queryMatch = line?.match(/^return\s+(\w+)\.query\((.+)\);$/);
    if (!queryMatch) {
      continue;
    }

    const args = splitTopLevelArgs(queryMatch[2]);
    const queryArg = args[0] ?? null;
    const paramsArg = args[1] ?? null;
    const queryParamIndex = params.indexOf(queryArg);
    const paramsParamIndex = params.indexOf(paramsArg);

    wrappers.set(name, {
      sink: 'db.query',
      sinkKind: 'sql',
      queryArgIndex: queryParamIndex,
      paramsArgIndex: paramsParamIndex,
      viaWrapper: true,
    });
  }

  return wrappers;
}

function resolveQueryCall(line, wrappers) {
  const directMatch = line.match(/^return\s+\w+\.query\((.+)\);$/);
  if (directMatch) {
    const args = splitTopLevelArgs(directMatch[1]);
    return {
      sink: 'db.query',
      sinkKind: 'sql',
      queryExpression: args[0] ?? null,
      paramsExpression: args[1] ?? null,
      parameterized: Boolean(args[1]),
      viaWrapper: false,
    };
  }

  const wrappedMatch = line.match(/^return\s+(\w+)\((.+)\);$/);
  if (!wrappedMatch) {
    return null;
  }

  const wrapper = wrappers.get(wrappedMatch[1]);
  if (!wrapper) {
    return null;
  }

  const args = splitTopLevelArgs(wrappedMatch[2]);
  const queryExpression = wrapper.queryArgIndex >= 0 ? (args[wrapper.queryArgIndex] ?? null) : null;
  const paramsExpression = wrapper.paramsArgIndex >= 0 ? (args[wrapper.paramsArgIndex] ?? null) : null;

  return {
    sink: wrapper.sink,
    sinkKind: wrapper.sinkKind,
    queryExpression,
    paramsExpression,
    parameterized: Boolean(paramsExpression),
    viaWrapper: true,
  };
}

export async function evaluateFile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const wrappers = buildWrapperMap(source);
  const handlerLines = extractHandlerLines(source);

  for (const rawLine of handlerLines) {
    const line = stripInlineComment(rawLine).trim();
    if (!line) {
      continue;
    }

    const resolved = resolveQueryCall(line, wrappers);
    if (resolved) {
      return resolved;
    }
  }

  return {
    sink: null,
    sinkKind: null,
    queryExpression: null,
    paramsExpression: null,
    parameterized: false,
    viaWrapper: false,
  };
}
