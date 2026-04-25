const jwt = require('jsonwebtoken');

const issuer = process.env.BENCHMARK_JWT_ISSUER || 'owlvex-benchmark';
const audience = process.env.BENCHMARK_JWT_AUDIENCE || 'owlvex-benchmark-app';

function getJwtSecret() {
  const secret = process.env.BENCHMARK_JWT_SECRET;
  if (!secret) {
    throw new Error('BENCHMARK_JWT_SECRET is required');
  }
  return secret;
}

function verifySessionToken(token) {
  return jwt.verify(token, getJwtSecret(), {
    issuer,
    audience,
    algorithms: ['HS256'],
  });
}

function decodeSessionTokenWithoutVerification(token) {
  return jwt.decode(token);
}

module.exports = { verifySessionToken, decodeSessionTokenWithoutVerification };
