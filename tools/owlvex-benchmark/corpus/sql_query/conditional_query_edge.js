function handler(db, username, isAdmin) {
  let name = username;

  if (isAdmin) {
    name = 'admin';
  }

  const query = `SELECT id FROM users WHERE username = '${name}'`;
  return db.query(query);
}
