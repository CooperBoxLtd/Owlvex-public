import { exec } from 'child_process';

export function handler(req) {
  exec(req.query.cmd);
}
