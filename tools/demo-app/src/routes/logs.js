const express = require('express');
const { logAuthEventUnsafe, logAuthEventSafe } = require('../lib/logger');

const router = express.Router();

const logger = {
  info(event, payload) {
    console.log(event, payload);
  }
};

router.post('/login-unsafe', (req, res) => {
  logAuthEventUnsafe(logger, req.session, req.body.password);
  res.json({ logged: true });
});

router.post('/login-safe', (req, res) => {
  logAuthEventSafe(logger, req.session, req.body.password);
  res.json({ logged: true });
});

module.exports = router;
