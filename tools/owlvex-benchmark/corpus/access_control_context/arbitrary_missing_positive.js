// Positive: arbitrary resource access with no authorization policy.
// The combination of ARBITRARY resource shape (docId passed directly to query)
// and MISSING policy check means there is no control preventing one user from
// reading another user's documents. Context is invalid — IDOR confirmed.
function handler(currentUser, docId, db) {
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
