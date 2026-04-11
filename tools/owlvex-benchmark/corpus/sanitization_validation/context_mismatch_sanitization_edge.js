import { exec } from 'child_process';

function escapeHtml(input) {
  return input.replace('<', '&lt;');
}

export function handler(req) {
  const cleaned = escapeHtml(req.query.cmd);
  exec(cleaned);
}
