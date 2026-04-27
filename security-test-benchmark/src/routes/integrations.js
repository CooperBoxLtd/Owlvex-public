const express = require('express');
const { requireUser } = require('../middleware/auth');
const { fetchAllowedPartner } = require('../lib/outboundHttp');

function createIntegrationRouter() {
  const router = express.Router();

  router.post('/proxy-unsafe', requireUser, async (req, res) => {
    const upstream = await fetch(req.body.url);
    const body = await upstream.text();
    res.type('text/plain').send(body);
  });

  router.post('/proxy-safe', requireUser, async (req, res) => {
    const upstream = await fetchAllowedPartner(req.body.partner);
    const body = await upstream.text();
    res.type('text/plain').send(body);
  });

  return router;
}

module.exports = { createIntegrationRouter };
