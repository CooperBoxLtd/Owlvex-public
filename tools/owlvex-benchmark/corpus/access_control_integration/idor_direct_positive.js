// Positive: direct IDOR — no authorization check, arbitrary resource access.
// A fully authenticated user can access any document by supplying its ID.
// There is no policy preventing cross-user data access.
function handler(currentUser, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
