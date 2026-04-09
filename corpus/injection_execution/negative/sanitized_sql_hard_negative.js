export async function findUser(db, userInput, sanitize) {
  const safeName = sanitize(userInput);
  const query = `SELECT * FROM users WHERE username = '${safeName}'`;
  return db.query(query);
}
