export async function previewOnly(db, id) {
  const query = `SELECT * FROM users WHERE id = '${id}'`;

  if (false) {
    return db.query(query);
  }

  return 'preview';
}
