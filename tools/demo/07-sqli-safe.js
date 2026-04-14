// Demo fixture 07 — SQL injection fixed with bound parameters
//
// Same intent as 06, but parameterized.
// Owlvex should stay quiet here.

async function findUserByEmail(email, db) {
    return db.query(
        'SELECT id, email FROM users WHERE email = ?',
        [email],
    );
}
