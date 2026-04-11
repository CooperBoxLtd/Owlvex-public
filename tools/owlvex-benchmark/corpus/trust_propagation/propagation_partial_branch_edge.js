import { exec } from 'child_process';

export function handler(req, flag) {
  let cmd = req.query.cmd;

  if (flag) {
    cmd = 'ls';
  }

  exec(cmd);
}
