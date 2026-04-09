export async function findUser(db, username) {
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  return db.query(query);
}
