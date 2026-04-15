const path = require('path');

const SAFE_EXTENSIONS = new Set(['.png', '.jpg', '.pdf']);

function buildUploadPath(fileName) {
  return path.join('/srv/uploads', fileName);
}

function buildSafeUploadPath(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  if (!SAFE_EXTENSIONS.has(ext)) {
    throw new Error('extension_not_allowed');
  }

  const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
  return path.join('/srv/uploads', safeName);
}

module.exports = {
  buildUploadPath,
  buildSafeUploadPath
};
