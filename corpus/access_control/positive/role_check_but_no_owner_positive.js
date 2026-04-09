export async function getUserById(db, req) {
  if (req.user.role === 'user') {
    return db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  }
}
