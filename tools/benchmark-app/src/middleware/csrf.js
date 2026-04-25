const crypto = require('crypto');

function timingSafeEquals(left, right) {
  const leftValue = Buffer.from(String(left || ''), 'utf8');
  const rightValue = Buffer.from(String(right || ''), 'utf8');
  if (leftValue.length !== rightValue.length) {
    return false;
  }
  return crypto.timingSafeEqual(leftValue, rightValue);
}

function requireCsrf(req, res, next) {
  const expected = req.cookies?.csrfToken;
  const supplied = req.header('x-csrf-token');
  if (!expected || !supplied || !timingSafeEquals(expected, supplied)) {
    res.status(403).json({ error: 'csrf_required' });
    return;
  }
  next();
}

module.exports = { requireCsrf };
