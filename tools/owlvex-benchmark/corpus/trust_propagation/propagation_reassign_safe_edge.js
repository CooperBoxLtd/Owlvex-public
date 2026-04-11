import { exec } from 'child_process';

export function handler(req) {
  let cmd = req.query.cmd;
  cmd = 'ls';

  exec(cmd);
}
