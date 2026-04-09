import { exec } from 'child_process';

export function fetchUrl(url, callback) {
  exec(`curl ${url}`, callback);
}
