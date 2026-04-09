import { exec } from 'child_process';

export function ping(host, cb) {
  exec(`ping -n 1 ${host}`, cb);
}
