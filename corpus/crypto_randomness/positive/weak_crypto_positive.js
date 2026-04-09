import crypto from 'crypto';

export function sign(value) {
  return crypto.createHash('md5').update(value).digest('hex');
}
