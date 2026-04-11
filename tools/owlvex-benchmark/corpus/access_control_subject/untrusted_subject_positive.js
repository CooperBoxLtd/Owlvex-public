// Positive: only caller-supplied identifier parameters present.
// userId and docId are provided by the caller — they are UNTRUSTED identifiers
// that could point to any user's resource.
function handler(userId, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
