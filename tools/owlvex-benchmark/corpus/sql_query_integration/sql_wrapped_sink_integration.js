// SQL integration: unsafe input → wrapped query helper → finding
// End-to-end: sink shape via wrapper + policy decision

function runQuery(db, text) {
  return db.query(text);
}

function handler(db, username) {
  const query = `SELECT id FROM users WHERE username = '${username}'`;
  return runQuery(db, query);
}
