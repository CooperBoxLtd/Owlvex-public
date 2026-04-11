// SQ-005 edge: generic sanitization applied before SQL interpolation
// generic character filtering does not prevent SQL injection

function sanitize(input) {
  return input.trim().toLowerCase();
}

function handler(db, username) {
  const cleaned = sanitize(username);
  const query = `SELECT id, email FROM users WHERE username = '${cleaned}'`;
  return db.query(query);
}
