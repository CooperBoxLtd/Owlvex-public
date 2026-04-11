// Negative: role-based access control check present.
// hasRole() verifies the user holds a role that grants access to this resource class.
// Role checks are a valid form of authorization policy for admin-level operations
// where all role holders may legitimately access any resource.
function handler(currentUser, docId, db) {
  hasRole(currentUser, 'admin');
  const doc = db.query('SELECT * FROM docs WHERE id = ?', [docId]);
  return doc;
}
