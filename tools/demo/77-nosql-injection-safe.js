// Demo fixture 77 - AI-focused safe NoSQL filtering
//
// Builds a narrow query from explicit allow-listed fields instead of trusting operators.

async function searchUsers(req, users) {
    const query = {};

    if (typeof req.body.email === 'string') {
        query.email = req.body.email.trim().toLowerCase();
    }

    if (req.body.active === true) {
        query.active = true;
    }

    return users.find(query).toArray();
}

module.exports = { searchUsers };
