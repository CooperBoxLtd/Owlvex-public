// SQ-003 edge: HTML escaping applied before SQL interpolation
// escapeHtml is not a SQL-safe transformation — still vulnerable

function escapeHtml(input) {
  return input.replace(/[<>&"']/g, '');
}

function handler(db, username) {
  const cleaned = escapeHtml(username);
  const query = `SELECT id, email FROM users WHERE username = '${cleaned}'`;
  return db.query(query);
}
