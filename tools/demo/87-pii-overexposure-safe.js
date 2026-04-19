// Demo fixture 87 - AI-focused safe profile projection
//
// Returns only the fields needed by the client.

async function getProfile(req, res, accounts) {
    const account = await accounts.findOne({ id: req.user.id });

    res.json({
        id: account.id,
        email: account.email,
        displayName: account.displayName,
    });
}

module.exports = { getProfile };
