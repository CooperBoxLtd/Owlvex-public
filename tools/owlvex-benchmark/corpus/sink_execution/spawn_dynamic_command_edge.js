import { spawn } from 'child_process';

export function handler(req) {
  const cmd = req.query.cmd;
  spawn(cmd, ['-la']);
}
