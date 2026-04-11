import { exec } from 'child_process';

function sanitize(input) {
  return input.replace(/[^a-z]/g, '');
}

export function handler(req) {
  const input = req.query.cmd;
  const cleaned = sanitize(input);

  exec(cleaned);
}
