import { spawn } from 'child_process';

export function pingHost(host) {
  const validatedHost = /^[a-z0-9.-]+$/i.test(host) ? host : '127.0.0.1';
  return spawn('ping', ['-n', '1', validatedHost], { shell: false });
}
