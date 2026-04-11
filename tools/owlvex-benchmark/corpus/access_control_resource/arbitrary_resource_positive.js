// Positive: resource access uses a caller-supplied identifier without session binding.
// docId is provided by the caller and passed directly as the WHERE clause argument.
// There is no constraint tying the lookup to the current user's resources.
function handler(currentUser, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
