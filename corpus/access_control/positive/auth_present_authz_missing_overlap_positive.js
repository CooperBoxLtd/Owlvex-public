export async function getInvoice(db, req) {
  if (req.user) {
    return db.query('SELECT * FROM invoices WHERE id = ?', [req.params.id]);
  }
}
