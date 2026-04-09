import { exec } from 'child_process';

export function runProbe(host, callback) {
  const password = 'P@ssw0rd-demo';
  exec(`ping -n 1 ${host}`, callback);
  return password;
}
