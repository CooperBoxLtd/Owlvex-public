// Demo fixture 78 - AI-focused mass assignment example
//
// Spreads the request body into a domain object and lets the client set privileged fields.

async function updateProfile(req, userRepository) {
    const patch = { ...req.body };
    await userRepository.update(req.user.id, patch);
    return { ok: true };
}

module.exports = { updateProfile };
