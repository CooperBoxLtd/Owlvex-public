// SQL integration: unsafe input → parameterized binding → no finding
// End-to-end: trust propagation + sink shape + policy decision

function handler(db, userId) {
  const query = 'SELECT * FROM orders WHERE user_id = $1';
  return db.query(query, [userId]);
}
