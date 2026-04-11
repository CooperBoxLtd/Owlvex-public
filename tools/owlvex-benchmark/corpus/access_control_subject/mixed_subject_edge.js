// Edge: both session-derived identity AND caller-supplied identifier present.
// currentUser provides the authenticated identity, but docId is a caller-supplied
// resource identifier. The mix makes IDOR analysis necessary.
function handler(currentUser, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
