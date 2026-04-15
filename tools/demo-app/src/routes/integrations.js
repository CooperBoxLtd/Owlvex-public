const express = require('express');
const { requireAdmin } = require('../middleware/auth');
const { isAllowedOutboundUrl } = require('../lib/urlPolicy');

const router = express.Router();

router.get('/fetch-unsafe', requireAdmin, async (req, res) => {
  const response = await fetch(req.query.url);
  const body = await response.text();
  res.json({ ok: true, body });
});

router.get('/fetch-safe', requireAdmin, async (req, res) => {
  if (!isAllowedOutboundUrl(req.query.url)) {
    return res.status(400).json({ error: 'outbound_url_blocked' });
  }

  const response = await fetch(req.query.url);
  const body = await response.text();
  res.json({ ok: true, body });
});

module.exports = router;
