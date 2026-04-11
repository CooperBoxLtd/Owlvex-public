// Negative: resource access is scoped to the current user's ID.
// The WHERE clause binds to currentUser.id — only the user's own documents
// can be returned. No IDOR risk at the resource shape level.
function handler(currentUser, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ? AND user_id = ?', [docId, currentUser.id]);
  return doc;
}
