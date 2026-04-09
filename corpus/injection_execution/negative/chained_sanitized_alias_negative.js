export async function findUser(db, input) {
  const safeName = sanitize(input);
  const alias = safeName;
  const finalName = alias;

  return db.query(`SELECT * FROM users WHERE name = '${finalName}'`);
}
