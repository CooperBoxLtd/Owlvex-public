import { evaluateFile as evaluateContextValidatedFile } from '../gr005/evaluator.mjs';

export async function evaluateFile(filePath) {
  const contextValidatedResult = await evaluateContextValidatedFile(filePath);

  if (!contextValidatedResult.sink) {
    return {
      ...contextValidatedResult,
      sink: null,
      trustStateAtSink: 'UNKNOWN',
      unsafeAtSink: false,
      finding: false,
    };
  }

  return {
    ...contextValidatedResult,
    finding: contextValidatedResult.dangerousInContext && contextValidatedResult.unsafeAtSink,
  };
}
