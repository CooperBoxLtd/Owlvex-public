function attachSession(req, _res, next) {
  req.session = {
    userId: req.headers['x-user-id'] || 'user-1',
    tenantId: req.headers['x-tenant-id'] || 'tenant-a',
    role: req.headers['x-role'] || 'user'
  };
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') {
    return res.status(403).json({ error: 'admin_only' });
  }
  next();
}

module.exports = {
  attachSession,
  requireAdmin
};
