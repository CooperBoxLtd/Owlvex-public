export async function getInvoice(db, req) {
  return db.query('SELECT * FROM invoices WHERE id = ?', [req.params.id]);
}
