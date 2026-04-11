// Negative: arbitrary resource access but with an explicit authorization policy.
// Even though docId is a caller-supplied identifier (ARBITRARY resource shape),
// the authorize() call verifies the current user has permission to access that
// specific resource. Context is valid — no IDOR.
function handler(currentUser, docId, db) {
  authorize(currentUser, 'read', docId);
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
