function runQuery(db, text) {
  return db.query(text);
}

function handler(db, username) {
  const query = `SELECT id FROM users WHERE username = '${username}'`;
  return runQuery(db, query);
}
