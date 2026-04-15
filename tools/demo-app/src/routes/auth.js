const express = require('express');
const { decodeJwtWithoutVerification, verifyJwtHmac } = require('../lib/tokens');

const router = express.Router();

router.get('/session-unsafe', (req, res) => {
  try {
    const claims = decodeJwtWithoutVerification(req.headers.authorization?.replace('Bearer ', ''));
    return res.json({
      ok: true,
      claims
    });
  } catch (error) {
    return res.status(401).json({ error: error.message });
  }
});

router.get('/session-safe', (req, res) => {
  try {
    const claims = verifyJwtHmac(req.headers.authorization?.replace('Bearer ', ''));
    return res.json({
      ok: true,
      claims
    });
  } catch (error) {
    return res.status(401).json({ error: error.message });
  }
});

module.exports = router;
