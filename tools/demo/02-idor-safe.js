// Demo fixture 02 — IDOR fixed: query scoped to current user
//
// Show this immediately after 01. No code explanation needed —
// the absence of a finding IS the explanation.

async function getDocument(currentUser, docId, db) {
    const doc = await db.query(
        'SELECT * FROM documents WHERE id = ? AND user_id = ?',
        [docId, currentUser.id],
    );
    return doc;
}
