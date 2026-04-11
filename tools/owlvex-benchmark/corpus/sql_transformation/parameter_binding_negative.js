// SQ-003 negative: parameterized binding applied
// user input passed as a bound parameter — SQL-safe

function handler(db, username) {
  const query = 'SELECT id, email FROM users WHERE username = $1';
  return db.query(query, [username]);
}
