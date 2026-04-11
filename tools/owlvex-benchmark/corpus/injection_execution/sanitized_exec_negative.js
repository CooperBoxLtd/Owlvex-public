import { exec } from 'child_process';

function sanitize(input) {
  return input.replace(/[^a-z]/g, '');
}

export function handler(req) {
  const cleaned = sanitize(req.query.cmd);
  exec(cleaned);
}
