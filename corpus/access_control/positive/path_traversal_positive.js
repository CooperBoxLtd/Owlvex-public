import path from 'path';
import fs from 'fs';

export function readFileFromUser(baseDir, requested) {
  return fs.readFileSync(path.join(baseDir, requested), 'utf8');
}
