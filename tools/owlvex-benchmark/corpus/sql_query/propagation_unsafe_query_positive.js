function handler(db, username) {
  const name = username;
  const query = `SELECT id FROM users WHERE username = '${name}'`;
  return db.query(query);
}
