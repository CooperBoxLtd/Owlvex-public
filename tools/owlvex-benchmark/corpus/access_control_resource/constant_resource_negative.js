// Negative: resource access uses a constant string key, not a caller-supplied ID.
// The WHERE clause uses a string literal — the resource is static and cannot be
// manipulated by the caller to access another user's data.
function handler(currentUser, db) {
  const config = db.query('SELECT * FROM system_config WHERE key = ?', ['app_version']);
  return config;
}
