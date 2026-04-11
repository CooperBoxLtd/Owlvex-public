import fs from 'node:fs/promises';

const EXECUTION_SINKS = {
  exec: { sinkKind: 'shell', argumentIndex: 0 },
  execSync: { sinkKind: 'shell', argumentIndex: 0 },
  spawn: { sinkKind: 'process', argumentIndex: 0 },
  spawnSync: { sinkKind: 'process', argumentIndex: 0 },
};

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

function isConstantString(expression) {
  const trimmed = expression.trim();
  return (
    (trimmed.startsWith('\'') && trimmed.endsWith('\'')) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith('`') && trimmed.endsWith('`'))
  );
}

function extractHandlerLines(source) {
  const lines = source.split(/\r?\n/);
  const startIndex = lines.findIndex((line) => line.includes('function handler('));
  if (startIndex === -1) {
    throw new Error('Could not find handler function.');
  }

  let balance = (lines[startIndex].match(/\{/g) || []).length - (lines[startIndex].match(/\}/g) || []).length;
  const blockLines = [];

  for (let index = startIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    balance += (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
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

function buildAliasMap(source) {
  const aliases = new Map();
  const lines = source.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = stripInlineComment(line).trim();
    const match = trimmed.match(/^const\s+(\w+)\s*=\s*(exec|execSync|spawn|spawnSync)\s*;$/);
    if (match) {
      aliases.set(match[1], match[2]);
    }
  }

  return aliases;
}

function buildWrapperMap(source, aliases) {
  const wrappers = new Map();
  const wrapperRegex = /function\s+(\w+)\(([^)]*)\)\s*\{([\s\S]*?)\}/g;
  let match;

  while ((match = wrapperRegex.exec(source)) !== null) {
    const [, name, paramList, body] = match;
    if (name === 'handler') {
      continue;
    }

    const params = paramList.split(',').map((param) => param.trim()).filter(Boolean);
    const bodyLine = body.split(/\r?\n/).map((line) => stripInlineComment(line).trim()).find(Boolean);
    const callMatch = bodyLine?.match(/^(\w+)\((.+)\);$/);
    if (!callMatch) {
      continue;
    }

    const callee = aliases.get(callMatch[1]) || callMatch[1];
    const sink = EXECUTION_SINKS[callee];
    if (!sink) {
      continue;
    }

    const args = splitTopLevelArgs(callMatch[2]);
    const forwardedParam = args[sink.argumentIndex];
    const paramIndex = params.indexOf(forwardedParam);
    if (paramIndex === -1) {
      continue;
    }

    wrappers.set(name, {
      sinkName: callee,
      sinkKind: sink.sinkKind,
      argumentIndex: paramIndex,
      viaWrapper: true,
    });
  }

  return wrappers;
}

function resolveSink(callee, aliases, wrappers) {
  if (wrappers.has(callee)) {
    return wrappers.get(callee);
  }

  const sinkName = aliases.get(callee) || callee;
  const base = EXECUTION_SINKS[sinkName];
  if (!base) {
    return null;
  }

  return {
    sinkName,
    sinkKind: base.sinkKind,
    argumentIndex: base.argumentIndex,
    viaWrapper: false,
  };
}

function parseCall(line) {
  const match = line.match(/^(\w+)\((.+)\);$/);
  if (!match) {
    return null;
  }

  return {
    callee: match[1],
    args: splitTopLevelArgs(match[2]),
  };
}

function hasShellTrue(optionsExpression) {
  return /\bshell\s*:\s*true\b/.test(optionsExpression);
}

function determineDangerousInContext(sink, args) {
  const relevantExpression = args[sink.argumentIndex] ?? null;
  const variable = relevantExpression && /^\w+$/.test(relevantExpression.trim())
    ? relevantExpression.trim()
    : null;
  if (!relevantExpression) {
    return {
      dangerousInContext: false,
      effectiveSinkKind: sink.sinkKind,
      expression: null,
      variable: null,
    };
  }

  if (sink.sinkName === 'exec' || sink.sinkName === 'execSync') {
    return {
      dangerousInContext: !isConstantString(relevantExpression),
      effectiveSinkKind: sink.sinkKind,
      expression: relevantExpression,
      variable,
    };
  }

  const optionsExpression = args[2] ?? '';
  const shellTrue = hasShellTrue(optionsExpression);
  if (shellTrue) {
    return {
      dangerousInContext: !isConstantString(relevantExpression),
      effectiveSinkKind: 'shell',
      expression: relevantExpression,
      variable,
    };
  }

  return {
    dangerousInContext: !isConstantString(relevantExpression),
    effectiveSinkKind: sink.sinkKind,
    expression: relevantExpression,
    variable,
  };
}

export async function evaluateFile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const aliases = buildAliasMap(source);
  const wrappers = buildWrapperMap(source, aliases);
  const handlerLines = extractHandlerLines(source);

  for (const rawLine of handlerLines) {
    const line = stripInlineComment(rawLine).trim();
    if (!line) {
      continue;
    }

    const call = parseCall(line);
    if (!call) {
      continue;
    }

    const sink = resolveSink(call.callee, aliases, wrappers);
    if (!sink) {
      continue;
    }

    const danger = determineDangerousInContext(sink, call.args);
    return {
      sink: sink.sinkName,
      sinkKind: danger.effectiveSinkKind,
      argumentIndex: sink.argumentIndex,
      dangerousInContext: danger.dangerousInContext,
      expression: danger.expression,
      variable: danger.variable,
      viaWrapper: sink.viaWrapper,
      aliasedCall: aliases.has(call.callee),
    };
  }

  return {
    sink: null,
    sinkKind: null,
    argumentIndex: null,
    dangerousInContext: false,
    expression: null,
    variable: null,
    viaWrapper: false,
    aliasedCall: false,
  };
}
