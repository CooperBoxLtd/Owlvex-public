const express = require('express');
const path = require('path');
const { requireUser } = require('../middleware/auth');
const { REPORT_ROOT, resolveReportPath } = require('../lib/reportCatalog');

function createReportRouter() {
  const router = express.Router();

  router.get('/download-unsafe', requireUser, async (req, res) => {
    const target = path.join(REPORT_ROOT, req.query.file);
    res.download(target);
  });

  router.get('/download-safe', requireUser, async (req, res) => {
    try {
      const target = resolveReportPath(req.query.reportId);
      res.download(target);
    } catch {
      res.status(404).json({ error: 'unknown_report' });
    }
  });

  return router;
}

module.exports = { createReportRouter };
