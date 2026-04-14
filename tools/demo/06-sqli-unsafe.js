// Demo fixture 06 — SQL injection via template literal
//
// The query text is built with direct interpolation.
// Owlvex should flag this as SQ-001.

async function findUserByEmail(email, db) {
    return db.query(
        `SELECT id, email FROM users WHERE email = '${email}'`,
    );
}
