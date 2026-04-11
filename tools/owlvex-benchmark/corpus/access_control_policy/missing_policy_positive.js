// Positive: no authorization check of any kind is present.
// The handler fetches a document by arbitrary ID without checking whether
// the current user is permitted to access it. This is a direct IDOR.
function handler(currentUser, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
