// Demo fixture 35 - SQL injection safe companion using parameter binding
//
// The user-controlled value is kept out of the SQL text and passed separately.
// Owlvex should keep this file clean.

function loadUser(req, db) {
    return db.query('SELECT * FROM users WHERE username = ?', [req.query.username]);
}
