import { exec } from 'child_process';

export function handler(req) {
  let cmd = 'ls';
  cmd = req.query.cmd;

  exec(cmd);
}
