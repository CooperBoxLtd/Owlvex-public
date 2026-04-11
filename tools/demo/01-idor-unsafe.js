// Demo fixture 01 — IDOR: caller-supplied identifier, no ownership check
//
// Ask the audience: "Can you spot the security issue?"
// Give them 10 seconds. Most won't see it immediately.

async function getDocument(currentUser, docId, db) {
    const doc = await db.query(
        'SELECT * FROM documents WHERE id = ?',
        [docId],
    );
    return doc;
}
