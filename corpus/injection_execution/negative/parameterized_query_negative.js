export async function findUser(db, username) {
  return db.query('SELECT * FROM users WHERE username = ?', [username]);
}
