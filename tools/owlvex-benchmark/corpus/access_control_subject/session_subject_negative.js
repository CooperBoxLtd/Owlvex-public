// Negative: only session-derived identity parameter present.
// The handler only receives the authenticated user — no caller-supplied resource ID.
function handler(currentUser, db) {
  const docs = db.query('SELECT * FROM docs WHERE user_id = ?', [currentUser.id]);
  return docs;
}
