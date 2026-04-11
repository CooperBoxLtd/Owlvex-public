// Edge: authentication check present but insufficient for object-level authorization.
// isAuthenticated() confirms the user is logged in, but does not verify that
// this specific user owns or has permission to access document docId.
// A logged-in user can still access another user's document — IDOR via auth-only.
function handler(currentUser, docId, db) {
  isAuthenticated(currentUser);
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
