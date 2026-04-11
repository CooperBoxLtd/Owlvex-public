// SQ-005 positive: HTML-oriented transformation reused in SQL context
// escapeHtml protects against XSS, not SQL injection

function escapeHtml(input) {
  return input.replace(/[<>&"']/g, '');
}

function handler(db, username) {
  const cleaned = escapeHtml(username);
  const query = `SELECT id, email FROM users WHERE username = '${cleaned}'`;
  return db.query(query);
}
