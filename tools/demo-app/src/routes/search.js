const express = require('express');
const { findUsersByEmailUnsafe, findUsersByEmailSafe } = require('../db');

const router = express.Router();

router.get('/users-unsafe', (req, res) => {
  const result = findUsersByEmailUnsafe(req.query.email);
  res.json(result);
});

router.get('/users-safe', (req, res) => {
  const result = findUsersByEmailSafe(req.query.email);
  res.json(result);
});

module.exports = router;
