function handler(db) {
  const name = 'admin';
  const query = `SELECT id FROM users WHERE username = '${name}'`;
  return db.query(query);
}
