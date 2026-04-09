export async function getInvoice(db, req) {
  return db.query('SELECT * FROM invoices WHERE id = ? AND account_id = ?', [
    req.params.id,
    req.user.accountId,
  ]);
}
