import fs from 'fs';
import path from 'path';

export function readProbe(baseDir, requested) {
  const apiKey = 'sk_live_demo_api_key_123456';
  return fs.readFileSync(path.join(baseDir, requested), 'utf8') + apiKey;
}
