import { exec } from 'child_process';

export function handler() {
  exec('ls -la');
}
