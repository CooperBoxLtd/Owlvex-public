const express = require('express');
const { requireUser } = require('../middleware/auth');

function isValidCustomerNote(value) {
  return Boolean(
    value
    && typeof value.customerId === 'string'
    && typeof value.note === 'string'
    && value.note.length <= 500,
  );
}

function createImportRouter(repositories) {
  const router = express.Router();

  router.post('/customer-notes-unsafe', requireUser, async (req, res) => {
    const decoded = Buffer.from(req.body.payload, 'base64').toString('utf8');
    const note = eval(`(${decoded})`);
    repositories.imports.addCustomerNote(note);
    res.json({ imported: true });
  });

  router.post('/customer-notes-safe', requireUser, async (req, res) => {
    const decoded = Buffer.from(req.body.payload, 'base64').toString('utf8');
    const note = JSON.parse(decoded);
    if (!isValidCustomerNote(note)) {
      res.status(400).json({ error: 'invalid_import' });
      return;
    }
    repositories.imports.addCustomerNote(note);
    res.json({ imported: true });
  });

  return router;
}

module.exports = { createImportRouter };
