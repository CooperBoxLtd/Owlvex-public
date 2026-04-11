// SQL integration: safe constant query, no user input involved → no finding
// End-to-end: trust propagation shows SAFE, no injection risk

function handler(db) {
  const query = 'SELECT COUNT(*) FROM users';
  return db.query(query);
}
