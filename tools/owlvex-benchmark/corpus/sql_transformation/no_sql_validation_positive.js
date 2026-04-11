// SQ-003 positive: no SQL-safe transformation applied
// user-controlled input interpolated directly into query text

function handler(db, username) {
  const query = `SELECT id, email FROM users WHERE username = '${username}'`;
  return db.query(query);
}
