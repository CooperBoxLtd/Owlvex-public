// Demo fixture 86 - AI-focused PII overexposure example
//
// Returns the whole account object, including sensitive fields, to the client.

async function getProfile(req, res, accounts) {
    const account = await accounts.findOne({ id: req.user.id });
    res.json(account);
}

module.exports = { getProfile };
