const express = require('express');
const fs = require('fs');
const { buildUploadPath, buildSafeUploadPath } = require('../lib/uploadPolicy');

const router = express.Router();

router.post('/unsafe', (req, res) => {
  const targetPath = buildUploadPath(req.body.fileName);
  fs.writeFileSync(targetPath, req.body.contents, 'utf8');
  res.json({ stored: true, path: targetPath });
});

router.post('/safe', (req, res) => {
  try {
    const targetPath = buildSafeUploadPath(req.body.fileName);
    fs.writeFileSync(targetPath, req.body.contents, 'utf8');
    return res.json({ stored: true, path: targetPath });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

module.exports = router;
