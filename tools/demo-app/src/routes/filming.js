const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const exportsDir = path.resolve(__dirname, '..', '..', 'exports');

const fakeUsers = [
  { id: 'u_1', email: 'alice@example.com', role: 'user' },
  { id: 'u_2', email: 'admin@example.com', role: 'admin' },
];

function matchesFilter(user, filter) {
  return Object.entries(filter).every(([key, value]) => user[key] === value);
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'authentication_required' });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }

  return next();
}

function toSafeUser(user) {
  return { id: user.id };
}

function resolveExportPath(requested) {
  if (typeof requested !== 'string' || requested.length === 0) {
    return null;
  }

  if (path.basename(requested) !== requested || path.extname(requested) !== '.txt') {
    return null;
  }

  const resolved = path.resolve(exportsDir, requested);
  const relative = path.relative(exportsDir, resolved);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return null;
  }

  return resolved;
}

router.post('/users/search-unsafe', requireAdmin, (req, res) => {
  const filter = req.body && typeof req.body.filter === 'object' && req.body.filter !== null ? req.body.filter : {};
  const results = fakeUsers.filter(user => matchesFilter(user, filter)).map(toSafeUser);
  res.json({ count: results.length, results });
});

router.post('/users/search-safe', requireAdmin, (req, res) => {
  const filter = {};

  if (typeof req.body.email === 'string') {
    filter.email = req.body.email;
  }

  if (typeof req.body.role === 'string' && ['user', 'admin'].includes(req.body.role)) {
    filter.role = req.body.role;
  }

  const results = fakeUsers.filter(user => matchesFilter(user, filter)).map(toSafeUser);
  res.json({ count: results.length, results });
});

router.get('/exports/unsafe', (req, res) => {
  const filePath = resolveExportPath(req.query.file);

  if (!filePath) {
    return res.status(400).json({ error: 'invalid_export' });
  }

  const report = fs.readFileSync(filePath, 'utf8');
  return res.type('text/plain').send(report);
});

router.get('/exports/safe', (req, res) => {
  const resolved = resolveExportPath(req.query.file);

  if (!resolved) {
    return res.status(400).json({ error: 'invalid_export' });
  }

  const report = fs.readFileSync(resolved, 'utf8');
  return res.type('text/plain').send(report);
});

module.exports = router;