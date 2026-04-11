function handler(db, username) {
  const query = `SELECT id, username FROM users WHERE username = '${username}'`;
  return db.query(query);
}
