const express = require('express');
const { requireUser } = require('../middleware/auth');
const { requireCsrf } = require('../middleware/csrf');

function createProfileRouter(repositories) {
  const router = express.Router();

  router.post('/email-unsafe', requireUser, async (req, res) => {
    const updated = repositories.users.updateEmail(req.user.id, req.body.email);
    res.json({ user: updated });
  });

  router.post('/email-safe', requireUser, requireCsrf, async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      res.status(400).json({ error: 'invalid_email' });
      return;
    }
    const updated = repositories.users.updateEmail(req.user.id, email);
    res.json({ user: updated });
  });

  return router;
}

module.exports = { createProfileRouter };
