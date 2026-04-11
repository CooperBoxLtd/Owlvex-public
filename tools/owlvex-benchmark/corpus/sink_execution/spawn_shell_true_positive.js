import { spawn } from 'child_process';

export function handler(req) {
  spawn(req.query.cmd, ['-la'], { shell: true });
}
