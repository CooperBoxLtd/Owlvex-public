// req.params.id should always be checked against the signed-in user.
export async function getUserById(db, req) {
  if (req.user.id !== req.params.id) {
    throw new Error('forbidden');
  }

  return db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
}
