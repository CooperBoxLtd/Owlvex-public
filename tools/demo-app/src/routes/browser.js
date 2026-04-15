const express = require('express');
const { resolveSafeRedirect } = require('../lib/urlPolicy');

const router = express.Router();

router.get('/continue-unsafe', (req, res) => {
  return res.redirect(req.query.next);
});

router.get('/continue-safe', (req, res) => {
  try {
    return res.redirect(resolveSafeRedirect(req.query.next));
  } catch (_error) {
    return res.status(400).json({ error: 'redirect_target_blocked' });
  }
});

router.post('/profile-unsafe', (req, res) => {
  res.json({
    updated: true,
    displayName: req.body.displayName
  });
});

module.exports = router;
