export async function findUser(db, input) {
  const safeName = sanitize(input);
  const alias = safeName;

  return db.query(`SELECT * FROM users WHERE name = '${alias}'`);
}
