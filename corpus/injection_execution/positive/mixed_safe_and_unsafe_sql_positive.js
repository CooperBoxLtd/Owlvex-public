export async function searchUsers(db, input) {
  const safeName = sanitize(input);
  const unsafeName = input;

  await db.query(`SELECT * FROM users WHERE name = '${safeName}'`);
  return db.query(`SELECT * FROM users WHERE name = '${unsafeName}'`);
}
