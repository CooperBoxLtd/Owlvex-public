import { exec } from 'child_process';

function validateInput(input) {
  return input.replace(/[^a-z]/g, '');
}

export function handler(req) {
  const cleaned = validateInput(req.query.cmd);
  exec(cleaned);
}
