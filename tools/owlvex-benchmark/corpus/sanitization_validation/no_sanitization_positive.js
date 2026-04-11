import { exec } from 'child_process';

export function handler(req) {
  const cmd = req.query.cmd;
  exec(cmd);
}
