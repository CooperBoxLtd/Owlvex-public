import { exec } from 'child_process';

function weakSanitize(input) {
  return input.replace(';', '');
}

export function handler(req) {
  const cleaned = weakSanitize(req.query.cmd);
  exec(cleaned);
}
