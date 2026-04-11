import { spawn } from 'child_process';

export function handler() {
  spawn('ls', ['-la']);
}
