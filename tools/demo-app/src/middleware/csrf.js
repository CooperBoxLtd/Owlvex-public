function requireCsrf(req, res, next) {
  const token = req.headers['x-csrf-token'];
  if (!token || token !== 'known-good-demo-token') {
    return res.status(403).json({ error: 'csrf_invalid' });
  }
  next();
}

module.exports = {
  requireCsrf
};
