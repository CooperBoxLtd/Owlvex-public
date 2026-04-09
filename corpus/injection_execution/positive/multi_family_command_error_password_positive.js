import { exec } from 'child_process';

export function runProbe(host, res, error, callback) {
  const password = 'P@ssw0rd-demo';
  exec(`ping -n 1 ${host}`, callback);
  return res.send(error.message || password);
}
