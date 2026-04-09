export async function loadUser(db, input) {
  const safeName = sanitize(input);

  function buildUnsafeQuery(value) {
    return `SELECT * FROM users WHERE name = '${value}'`;
  }

  await db.query(`SELECT * FROM users WHERE alias = '${safeName}'`);
  return db.query(buildUnsafeQuery(input));
}
