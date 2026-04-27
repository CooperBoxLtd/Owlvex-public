const express = require('express');
const { requireUser } = require('../middleware/auth');
const { canReadDocument } = require('../policies/accessPolicy');

function createDocumentRouter(repositories) {
  const router = express.Router();

  router.get('/:documentId/unsafe', requireUser, async (req, res) => {
    const document = repositories.documents.findById(req.params.documentId);
    if (!document) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    res.json(document);
  });

  router.get('/:documentId/safe', requireUser, async (req, res) => {
    const document = repositories.documents.findForTenant(req.params.documentId, req.user.tenantId);
    if (!canReadDocument(req.user, document)) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    res.json(document);
  });

  return router;
}

module.exports = { createDocumentRouter };
