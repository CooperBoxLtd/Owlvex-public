// Demo fixture 14 — HTML sanitizer used in SQL context
//
// escapeHtml is valid for HTML, not SQL. The query is still injectable.
// Owlvex should flag this as SQ-001 with context mismatch wording.

function escapeHtml(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

async function findUserByName(name, db) {
    const cleaned = escapeHtml(name);
    const query = `SELECT id FROM users WHERE name = '${cleaned}'`;
    return db.query(query);
}
