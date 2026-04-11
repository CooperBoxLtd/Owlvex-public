// SQL integration: unsafe input → HTML escaping → interpolated query → context mismatch finding
// End-to-end: trust propagation + wrong transformation + context validation + policy decision

function escapeHtml(input) {
  return input.replace(/[<>&"']/g, '');
}

function handler(db, userId) {
  const safeId = escapeHtml(userId);
  const query = `SELECT * FROM orders WHERE user_id = '${safeId}'`;
  return db.query(query);
}
