function handler(db, username) {
  const query = 'SELECT id, username FROM users WHERE username = $1';
  return db.query(query, [username]);
}
