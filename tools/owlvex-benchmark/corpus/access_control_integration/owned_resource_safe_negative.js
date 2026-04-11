// Negative: resource access is scoped to the current user's documents.
// The query binds both the docId and currentUser.id — the database enforces
// that only the authenticated user's documents are returned. No IDOR risk.
function handler(currentUser, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ? AND user_id = ?', [docId, currentUser.id]);
  return doc;
}
