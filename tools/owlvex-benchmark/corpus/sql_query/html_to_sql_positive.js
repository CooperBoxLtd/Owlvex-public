function escapeHtml(input) {
  return input.replace(/[<>]/g, '');
}

function handler(db, username) {
  const cleaned = escapeHtml(username);
  const query = `SELECT id FROM users WHERE username = '${cleaned}'`;
  return db.query(query);
}
