import { exec } from 'child_process';

export function runProbe(host, callback) {
  const debug = "SELECT * FROM users WHERE id = '" + host + "'";
  exec(`ping -n 1 ${host}`, callback);
  return debug;
}
