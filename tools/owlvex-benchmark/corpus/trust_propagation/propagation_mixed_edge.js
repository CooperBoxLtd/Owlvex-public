import { exec } from 'child_process';

export function handler(req, isAdmin) {
  let cmd;

  if (isAdmin) {
    cmd = 'ls';
  } else {
    cmd = req.query.cmd;
  }

  exec(cmd);
}
