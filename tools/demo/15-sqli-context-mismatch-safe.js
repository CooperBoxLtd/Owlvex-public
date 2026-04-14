// Demo fixture 15 — SQL context fixed with parameterization
//
// Even if input is validated elsewhere, SQL safety comes from binding.
// Owlvex should stay quiet here.

function escapeHtml(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

async function findUserByName(name, db) {
    const cleaned = escapeHtml(name);
    return db.query(
        'SELECT id FROM users WHERE name = ?',
        [cleaned],
    );
}
