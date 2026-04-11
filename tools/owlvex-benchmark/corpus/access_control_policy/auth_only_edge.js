// Edge: only an authentication check is present — not an authorization check.
// isAuthenticated() confirms the user is logged in but does not verify whether
// they are permitted to access this specific document. Authentication ≠ authorization.
// This pattern is insufficient and produces a finding.
function handler(currentUser, docId, db) {
  isAuthenticated(currentUser);
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
