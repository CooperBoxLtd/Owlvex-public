const crypto = require('crypto');

const DEMO_SECRET = 'owlvex-demo-secret';

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

function decodeJwtWithoutVerification(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    throw new Error('token_format_invalid');
  }

  return decodeSegment(parts[1]);
}

function verifyJwtHmac(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    throw new Error('token_format_invalid');
  }

  const [header, payload, signature] = parts;
  const expected = crypto
    .createHmac('sha256', DEMO_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');

  if (signature !== expected) {
    throw new Error('signature_invalid');
  }

  const claims = decodeSegment(payload);
  if (claims.iss !== 'owlvex-demo' || claims.aud !== 'owlvex-demo-app') {
    throw new Error('claims_invalid');
  }

  return claims;
}

module.exports = {
  decodeJwtWithoutVerification,
  verifyJwtHmac
};
