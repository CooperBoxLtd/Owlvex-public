// Demo fixture 76 - AI-focused NoSQL injection example
//
// Passes a client-controlled Mongo-style filter object directly into a query.

async function searchUsers(req, users) {
    const filter = req.body.filter;
    return users.find(filter).toArray();
}

module.exports = { searchUsers };
