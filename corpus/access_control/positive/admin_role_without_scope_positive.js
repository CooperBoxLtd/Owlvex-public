export async function getCustomer(db, req) {
  if (req.user.role === 'admin') {
    return db.query('SELECT * FROM customers WHERE id = ?', [req.params.id]);
  }
}
