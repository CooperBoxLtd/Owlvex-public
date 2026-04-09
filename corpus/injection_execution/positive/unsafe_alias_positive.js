export async function findUser(db, input) {
  const alias = input;

  return db.query(`SELECT * FROM users WHERE name = '${alias}'`);
}
