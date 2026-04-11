// Negative: explicit authorization check present before arbitrary resource access.
// authorize() performs a full permission check for the specific (user, action, resource)
// tuple. Even though docId is caller-supplied, the policy gate prevents unauthorized access.
function handler(currentUser, docId, db) {
  authorize(currentUser, 'read', docId);
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
