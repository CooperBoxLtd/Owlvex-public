export async function searchUsers(db, input, teamId) {
  const safeName = sanitize(input);
  const safeTeam = sanitize(teamId);
  const unsafeName = input;

  await db.query(`SELECT * FROM users WHERE team = '${safeTeam}'`);
  await db.query(`SELECT * FROM users WHERE name = '${safeName}'`);
  return db.query(`SELECT * FROM users WHERE alias = '${unsafeName}'`);
}
