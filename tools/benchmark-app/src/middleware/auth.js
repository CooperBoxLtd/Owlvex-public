const { verifySessionToken } = require('../lib/tokens');

function attachCurrentUser(users) {
  return async function currentUserMiddleware(req, _res, next) {
    const token = req.cookies?.session || req.header('authorization')?.replace(/^Bearer\s+/i, '');
    if (!token) {
      req.user = null;
      next();
      return;
    }

    try {
      const claims = verifySessionToken(token);
      req.user = users.findById(claims.sub);
    } catch {
      req.user = null;
    }

    next();
  };
}

function requireUser(req, res, next) {
  if (!req.user) {
    res.status(401).json({ error: 'auth_required' });
    return;
  }
  next();
}

module.exports = { attachCurrentUser, requireUser };
