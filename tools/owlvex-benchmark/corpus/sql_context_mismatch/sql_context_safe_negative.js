// SQ-005 negative: parameterized binding — correct SQL context
// user input is bound via parameters, not interpolated into query text

function handler(db, username) {
  const query = 'SELECT id, email FROM users WHERE username = $1';
  return db.query(query, [username]);
}
