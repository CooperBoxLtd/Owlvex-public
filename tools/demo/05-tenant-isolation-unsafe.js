// Demo fixture 05 — Multi-tenant isolation failure
//
// Optional: swap this in for Beat 2 when presenting to SaaS companies
// or enterprise security teams. The impact statement lands harder.
//
// tenantId is accepted but not included in the query.
// Every user in every tenant can read every other tenant's documents.

async function getDocuments(currentUser, tenantId, db) {
    const docs = await db.query(
        'SELECT * FROM documents WHERE user_id = ?',
        [currentUser.id],
    );
    return docs;
}
