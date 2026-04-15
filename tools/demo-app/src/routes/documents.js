const express = require('express');
const { getDocumentById, getDocumentForUser, getDocumentForTenant } = require('../db');

const router = express.Router();

router.get('/unsafe/:id', (req, res) => {
  const doc = getDocumentById(req.params.id);
  if (!doc) {
    return res.status(404).json({ error: 'not_found' });
  }
  res.json(doc);
});

router.get('/safe-user/:id', (req, res) => {
  const doc = getDocumentForUser(req.params.id, req.session.userId);
  if (!doc) {
    return res.status(404).json({ error: 'not_found' });
  }
  res.json(doc);
});

router.get('/safe-tenant/:id', (req, res) => {
  const doc = getDocumentForTenant(req.params.id, req.session.tenantId);
  if (!doc) {
    return res.status(404).json({ error: 'not_found' });
  }
  res.json(doc);
});

module.exports = router;
