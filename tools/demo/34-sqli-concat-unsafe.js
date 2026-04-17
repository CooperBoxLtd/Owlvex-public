// Demo fixture 34 - SQL injection through string concatenation
//
// Concatenating request-derived values into SQL text is still raw SQL assembly.
// Owlvex should flag this as deterministic SQL injection.

function loadUser(req, db) {
    const query = "SELECT * FROM users WHERE username = '" + req.query.username + "'";
    return db.query(query);
}
