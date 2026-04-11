// SQL integration: unsafe input → no transformation → interpolated query → finding
// End-to-end: trust propagation + sink shape + policy decision

function handler(db, userId) {
  const query = `SELECT * FROM orders WHERE user_id = '${userId}'`;
  return db.query(query);
}
