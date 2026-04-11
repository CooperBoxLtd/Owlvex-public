import { spawn } from 'child_process';

export function handler(req) {
  spawn('ls', [req.query.cmd]);
}
