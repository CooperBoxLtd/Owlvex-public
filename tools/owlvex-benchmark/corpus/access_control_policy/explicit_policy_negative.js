// Negative: an explicit authorization call is present before the query.
// authorize() performs a full permission check — verifying the caller has
// the right to access the specific resource. This is a sufficient policy.
function handler(currentUser, docId, db) {
  authorize(currentUser, 'read', docId);
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
