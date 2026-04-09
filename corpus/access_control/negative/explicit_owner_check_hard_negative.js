export async function getUserById(db, req) {
  if (req.user.id !== req.params.id) {
    throw new Error('forbidden');
  }

  return db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
}
